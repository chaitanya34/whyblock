package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

// GetInstance fetches EC2 instance metadata by instance ID.
// Returns InstanceData with all fields needed for layer analysis.
func (c *Client) GetInstance(ctx context.Context, instanceId string) (InstanceData, error) {

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceId},
	}

	instanceResult, err := c.ec2Client.DescribeInstances(ctx, input)
	if err != nil {
		return InstanceData{}, mapInstanceError(err, instanceId)
	}

	// DescribeInstances returns a list of Reservations.
	// A Reservation is a group of instances launched together.
	// We asked for one specific instance ID so we expect exactly
	// one reservation with exactly one instance.
	if len(instanceResult.Reservations) == 0 || len(instanceResult.Reservations[0].Instances) == 0 {
		return InstanceData{}, fmt.Errorf("instance %s not found", instanceId)
	}

	return mapInstance(instanceResult.Reservations[0].Instances[0]), nil

}

// GetEIP checks if the instance has an Elastic IP associated.
// Returns the EIP public IP string, or empty string if none.
func (c *Client) GetEIP(ctx context.Context, instanceID string) (string, error) {
	input := &ec2.DescribeAddressesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("instance-id"),
				Values: []string{instanceID},
			},
		},
	}

	resp, err := c.ec2Client.DescribeAddresses(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to describe addresses for %s: %w", instanceID, err)
	}

	if len(resp.Addresses) == 0 {
		return "", nil
	}

	// an instance can only have one EIP at a time
	if resp.Addresses[0].PublicIp == nil {
		return "", nil
	}

	return aws.ToString(resp.Addresses[0].PublicIp), nil
}

// mapInstance converts the AWS SDK instance type into our internal InstanceData.
// All SDK pointer dereferences are handled safely here in one place.
func mapInstance(i types.Instance) InstanceData {
	data := InstanceData{
		InstanceID: aws.ToString(i.InstanceId),
		PrivateIP:  aws.ToString(i.PrivateIpAddress),
		VPCID:      aws.ToString(i.VpcId),
		SubnetID:   aws.ToString(i.SubnetId),
		State:      string(i.State.Name),
	}

	// PublicIpAddress is the auto-assigned public IP (changes on stop/start)
	// EIP is handled separately in GetEIP
	if i.PublicIpAddress != nil {
		data.PublicIP = aws.ToString(i.PublicIpAddress)
	}

	// collect all attached security group IDs
	data.SecurityGroups = make([]string, 0, len(i.SecurityGroups))
	for _, sg := range i.SecurityGroups {
		if sg.GroupId != nil {
			data.SecurityGroups = append(data.SecurityGroups, aws.ToString(sg.GroupId))
		}
	}

	return data
}

// mapInstanceError converts AWS API errors into clear user-facing messages.
func mapInstanceError(err error, instanceID string) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "InvalidInstanceID.NotFound":
			return fmt.Errorf("instance %s not found — check the instance ID and region", instanceID)
		case "InvalidInstanceID.Malformed":
			return fmt.Errorf("invalid instance ID format %q — expected format: i-0abc1234567890abc", instanceID)
		}

		if isAccessDenied(err) {
			return fmt.Errorf("permission denied — missing ec2:DescribeInstances")
		}
	}

	return fmt.Errorf("failed to describe instance %s: %w", instanceID, err)
}
