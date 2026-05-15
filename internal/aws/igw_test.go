package aws

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestIsAttachedToVPC(t *testing.T) {
	tests := []struct {
		name        string
		attachments []types.InternetGatewayAttachment
		vpcID       string
		expected    bool
	}{
		{
			name: "attached to correct VPC",
			attachments: []types.InternetGatewayAttachment{
				{
					VpcId: aws.String("vpc-0abc123"),
					State: types.AttachmentStatusAttached,
				},
			},
			vpcID:    "vpc-0abc123",
			expected: true,
		},
		{
			name: "IGW exists but in detaching state",
			attachments: []types.InternetGatewayAttachment{
				{
					VpcId: aws.String("vpc-0abc123"),
					State: types.AttachmentStatusDetaching,
				},
			},
			vpcID:    "vpc-0abc123",
			expected: false,
		},
		{
			name: "IGW exists but in detached state",
			attachments: []types.InternetGatewayAttachment{
				{
					VpcId: aws.String("vpc-0abc123"),
					State: types.AttachmentStatusDetached,
				},
			},
			vpcID:    "vpc-0abc123",
			expected: false,
		},
		{
			name: "IGW attached to different VPC",
			attachments: []types.InternetGatewayAttachment{
				{
					VpcId: aws.String("vpc-different"),
					State: types.AttachmentStatusAttached,
				},
			},
			vpcID:    "vpc-0abc123",
			expected: false,
		},
		{
			name:        "no attachments at all",
			attachments: []types.InternetGatewayAttachment{},
			vpcID:       "vpc-0abc123",
			expected:    false,
		},
		{
			name: "multiple attachments — correct VPC is attached",
			attachments: []types.InternetGatewayAttachment{
				{
					VpcId: aws.String("vpc-other1"),
					State: types.AttachmentStatusAttached,
				},
				{
					VpcId: aws.String("vpc-0abc123"),
					State: types.AttachmentStatusAttached,
				},
			},
			vpcID:    "vpc-0abc123",
			expected: true,
		},
		{
			name: "nil VPC ID in attachment — should not panic",
			attachments: []types.InternetGatewayAttachment{
				{
					VpcId: nil,
					State: types.AttachmentStatusAttached,
				},
			},
			vpcID:    "vpc-0abc123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAttachedToVPC(tt.attachments, tt.vpcID)
			if got != tt.expected {
				t.Errorf("isAttachedToVPC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMapIGWError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		vpcID          string
		expectedSubstr string
	}{
		{
			name:           "access denied",
			err:            &mockAPIError{code: "UnauthorizedOperation"},
			vpcID:          "vpc-0abc123",
			expectedSubstr: "permission denied",
		},
		{
			name:           "unknown error wrapped with vpcID",
			err:            &mockAPIError{code: "InternalError"},
			vpcID:          "vpc-0abc123",
			expectedSubstr: "vpc-0abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapIGWError(tt.err, tt.vpcID)
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
