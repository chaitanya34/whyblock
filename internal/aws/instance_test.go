package aws

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestMapInstance(t *testing.T) {
	tests := []struct {
		name     string
		input    types.Instance
		expected InstanceData
	}{
		{
			name: "fully populated instance",
			input: types.Instance{
				InstanceId:       aws.String("i-0abc123"),
				PublicIpAddress:  aws.String("52.14.0.1"),
				PrivateIpAddress: aws.String("10.0.1.5"),
				VpcId:            aws.String("vpc-0def456"),
				SubnetId:         aws.String("subnet-0ghi789"),
				State:            &types.InstanceState{Name: types.InstanceStateNameRunning},
				SecurityGroups: []types.GroupIdentifier{
					{GroupId: aws.String("sg-001")},
					{GroupId: aws.String("sg-002")},
				},
			},
			expected: InstanceData{
				InstanceID:     "i-0abc123",
				PublicIP:       "52.14.0.1",
				PrivateIP:      "10.0.1.5",
				VPCID:          "vpc-0def456",
				SubnetID:       "subnet-0ghi789",
				State:          "running",
				SecurityGroups: []string{"sg-001", "sg-002"},
			},
		},
		{
			name: "instance with no public IP",
			input: types.Instance{
				InstanceId:       aws.String("i-0abc123"),
				PrivateIpAddress: aws.String("10.0.2.5"),
				VpcId:            aws.String("vpc-0def456"),
				SubnetId:         aws.String("subnet-0ghi789"),
				State:            &types.InstanceState{Name: types.InstanceStateNameRunning},
				SecurityGroups:   []types.GroupIdentifier{},
			},
			expected: InstanceData{
				InstanceID:     "i-0abc123",
				PublicIP:       "", // no public IP
				PrivateIP:      "10.0.2.5",
				VPCID:          "vpc-0def456",
				SubnetID:       "subnet-0ghi789",
				State:          "running",
				SecurityGroups: []string{},
			},
		},
		{
			name: "stopped instance",
			input: types.Instance{
				InstanceId:       aws.String("i-0abc123"),
				PrivateIpAddress: aws.String("10.0.1.5"),
				VpcId:            aws.String("vpc-0def456"),
				SubnetId:         aws.String("subnet-0ghi789"),
				State:            &types.InstanceState{Name: types.InstanceStateNameStopped},
				SecurityGroups:   []types.GroupIdentifier{},
			},
			expected: InstanceData{
				InstanceID:     "i-0abc123",
				PublicIP:       "",
				PrivateIP:      "10.0.1.5",
				VPCID:          "vpc-0def456",
				SubnetID:       "subnet-0ghi789",
				State:          "stopped",
				SecurityGroups: []string{},
			},
		},
		{
			name: "instance with nil security group ID skipped",
			input: types.Instance{
				InstanceId:       aws.String("i-0abc123"),
				PrivateIpAddress: aws.String("10.0.1.5"),
				VpcId:            aws.String("vpc-0def456"),
				SubnetId:         aws.String("subnet-0ghi789"),
				State:            &types.InstanceState{Name: types.InstanceStateNameRunning},
				SecurityGroups: []types.GroupIdentifier{
					{GroupId: aws.String("sg-001")},
					{GroupId: nil}, // malformed — should be skipped
				},
			},
			expected: InstanceData{
				InstanceID:     "i-0abc123",
				PrivateIP:      "10.0.1.5",
				VPCID:          "vpc-0def456",
				SubnetID:       "subnet-0ghi789",
				State:          "running",
				SecurityGroups: []string{"sg-001"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapInstance(tt.input)

			if got.InstanceID != tt.expected.InstanceID {
				t.Errorf("InstanceID: got %q want %q", got.InstanceID, tt.expected.InstanceID)
			}
			if got.PublicIP != tt.expected.PublicIP {
				t.Errorf("PublicIP: got %q want %q", got.PublicIP, tt.expected.PublicIP)
			}
			if got.PrivateIP != tt.expected.PrivateIP {
				t.Errorf("PrivateIP: got %q want %q", got.PrivateIP, tt.expected.PrivateIP)
			}
			if got.State != tt.expected.State {
				t.Errorf("State: got %q want %q", got.State, tt.expected.State)
			}
			if len(got.SecurityGroups) != len(tt.expected.SecurityGroups) {
				t.Errorf("SecurityGroups length: got %d want %d",
					len(got.SecurityGroups), len(tt.expected.SecurityGroups))
				return
			}
			for i := range tt.expected.SecurityGroups {
				if got.SecurityGroups[i] != tt.expected.SecurityGroups[i] {
					t.Errorf("SecurityGroups[%d]: got %q want %q",
						i, got.SecurityGroups[i], tt.expected.SecurityGroups[i])
				}
			}
		})
	}
}

func TestMapInstanceError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		instanceID     string
		expectedSubstr string
	}{
		{
			name:           "instance not found",
			err:            &mockAPIError{code: "InvalidInstanceID.NotFound"},
			instanceID:     "i-0abc123",
			expectedSubstr: "not found",
		},
		{
			name:           "malformed instance ID",
			err:            &mockAPIError{code: "InvalidInstanceID.Malformed"},
			instanceID:     "bad-id",
			expectedSubstr: "invalid instance ID format",
		},
		{
			name:           "access denied",
			err:            &mockAPIError{code: "UnauthorizedOperation"},
			instanceID:     "i-0abc123",
			expectedSubstr: "permission denied",
		},
		{
			name:           "unknown error wrapped",
			err:            &mockAPIError{code: "InternalError"},
			instanceID:     "i-0abc123",
			expectedSubstr: "failed to describe instance",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapInstanceError(tt.err, tt.instanceID)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.expectedSubstr) {
				t.Errorf("expected error containing %q, got: %q",
					tt.expectedSubstr, err.Error())
			}
		})
	}
}
