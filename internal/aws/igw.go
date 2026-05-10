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

// GetIGW checks whether an Internet Gateway is attached to the given VPC.
// Returns an IGW struct with Attached=false if no IGW exists.
func (c *Client) GetIGW(ctx context.Context, vpcID string) (IGW, error) {
	input := &ec2.DescribeInternetGatewaysInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("attachment.vpc-id"),
				Values: []string{vpcID},
			},
		},
	}
	resp, err := c.ec2Client.DescribeInternetGateways(ctx, input)
	if err != nil {
		return IGW{}, mapIGWError(err, vpcID)
	}

	// no IGW found for this VPC — valid case, not an error
	// means the VPC has no internet connectivity
	if len(resp.InternetGateways) == 0 {
		return IGW{Attached: false}, nil
	}

	// why only check the first IGW? AWS allows multiple IGWs but only one can be attached to a VPC at a time.
	igw := resp.InternetGateways[0]

	return IGW{
		ID:       aws.ToString(igw.InternetGatewayId),
		Attached: isAttachedToVPC(igw.Attachments, vpcID),
	}, nil

}

// isAttachedToVPC checks the IGW attachment list to confirm it is
// actively attached to the given VPC.
// An IGW can exist but be in "detaching" state — we must verify.
func isAttachedToVPC(attachments []types.InternetGatewayAttachment, vpcID string) bool {
	for _, a := range attachments {
		if aws.ToString(a.VpcId) == vpcID &&
			a.State == types.AttachmentStatusAttached {
			return true
		}
	}
	return false
}

// mapIGWError converts AWS API errors into clear user-facing messages.
func mapIGWError(err error, vpcID string) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if isAccessDenied(err) {
			return fmt.Errorf("permission denied — missing ec2:DescribeInternetGateways")
		}
	}
	return fmt.Errorf("failed to describe internet gateway for VPC %s: %w", vpcID, err)
}
