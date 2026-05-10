package analyzer

import (
	"testing"

	"github.com/chaitanya34/whyblock/internal/aws"
	"github.com/chaitanya34/whyblock/internal/model"
)

func TestCheckPublicIP(t *testing.T) {
	tests := []struct {
		name           string
		instance       aws.InstanceData
		eip            string
		expectedStatus model.LayerStatus
		expectedDetail string
	}{
		{
			name:           "has auto-assigned public IP",
			instance:       aws.InstanceData{PublicIP: "52.14.0.1"},
			eip:            "",
			expectedStatus: model.StatusAllow,
			expectedDetail: "52.14.0.1",
		},
		{
			name:           "has EIP — shown over auto IP",
			instance:       aws.InstanceData{PublicIP: "52.14.0.1"},
			eip:            "18.220.0.1",
			expectedStatus: model.StatusAllow,
			expectedDetail: "18.220.0.1",
		},
		{
			name:           "no public IP and no EIP — blocked",
			instance:       aws.InstanceData{PublicIP: ""},
			eip:            "",
			expectedStatus: model.StatusBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkPublicIP(tt.instance, tt.eip)

			if result.Status != tt.expectedStatus {
				t.Errorf("Status = %q, want %q", result.Status, tt.expectedStatus)
			}
			if tt.expectedDetail != "" && result.Detail != tt.expectedDetail {
				t.Errorf("Detail = %q, want %q", result.Detail, tt.expectedDetail)
			}
			if result.Status == model.StatusBlock && result.FixHint == "" {
				t.Error("blocked layer must have a FixHint")
			}
		})
	}
}

func TestCollectAllowedPorts(t *testing.T) {
	tests := []struct {
		name     string
		sgs      []aws.SecurityGroup
		protocol string
		expected string
	}{
		{
			name: "single port",
			sgs: []aws.SecurityGroup{{
				Rules: []aws.SGRule{
					{Direction: "inbound", Protocol: "tcp", FromPort: 80, ToPort: 80},
				},
			}},
			protocol: "tcp",
			expected: "80",
		},
		{
			name: "multiple ports",
			sgs: []aws.SecurityGroup{{
				Rules: []aws.SGRule{
					{Direction: "inbound", Protocol: "tcp", FromPort: 80, ToPort: 80},
					{Direction: "inbound", Protocol: "tcp", FromPort: 22, ToPort: 22},
				},
			}},
			protocol: "tcp",
			expected: "80, 22",
		},
		{
			name: "port range",
			sgs: []aws.SecurityGroup{{
				Rules: []aws.SGRule{
					{Direction: "inbound", Protocol: "tcp", FromPort: 8000, ToPort: 9000},
				},
			}},
			protocol: "tcp",
			expected: "8000-9000",
		},
		{
			name: "all traffic rule included for any protocol",
			sgs: []aws.SecurityGroup{{
				Rules: []aws.SGRule{
					{Direction: "inbound", Protocol: "-1", FromPort: 0, ToPort: 0},
				},
			}},
			protocol: "tcp",
			expected: "0",
		},
		{
			name: "outbound rules excluded",
			sgs: []aws.SecurityGroup{{
				Rules: []aws.SGRule{
					{Direction: "outbound", Protocol: "tcp", FromPort: 443, ToPort: 443},
				},
			}},
			protocol: "tcp",
			expected: "none",
		},
		{
			name:     "no rules at all",
			sgs:      []aws.SecurityGroup{},
			protocol: "tcp",
			expected: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectAllowedPorts(tt.sgs, tt.protocol)
			if got != tt.expected {
				t.Errorf("collectAllowedPorts() = %q, want %q", got, tt.expected)
			}
		})
	}
}
