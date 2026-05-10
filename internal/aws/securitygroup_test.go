package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestEvaluateSG(t *testing.T) {
	tests := []struct {
		name            string
		sgs             []SecurityGroup
		port            int
		protocol        string
		srcIP           string
		expectedAllowed bool
		expectedCIDR    string
	}{
		{
			name: "port allowed by exact rule",
			sgs: []SecurityGroup{
				{
					ID:   "sg-001",
					Name: "web-sg",
					Rules: []SGRule{
						{Direction: "inbound", Protocol: "tcp",
							FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0"},
					},
				},
			},
			port:            443,
			protocol:        "tcp",
			srcIP:           "203.0.113.5",
			expectedAllowed: true,
			expectedCIDR:    "0.0.0.0/0",
		},
		{
			name: "port not in any rule — implicit deny",
			sgs: []SecurityGroup{
				{
					ID:   "sg-001",
					Name: "web-sg",
					Rules: []SGRule{
						{Direction: "inbound", Protocol: "tcp",
							FromPort: 80, ToPort: 80, CIDR: "0.0.0.0/0"},
						{Direction: "inbound", Protocol: "tcp",
							FromPort: 22, ToPort: 22, CIDR: "10.0.0.0/8"},
					},
				},
			},
			port:            443,
			protocol:        "tcp",
			srcIP:           "203.0.113.5",
			expectedAllowed: false,
		},
		{
			name: "all-traffic rule allows any port",
			sgs: []SecurityGroup{
				{
					ID:   "sg-001",
					Name: "open-sg",
					Rules: []SGRule{
						{Direction: "inbound", Protocol: "-1",
							FromPort: 0, ToPort: 0, CIDR: "0.0.0.0/0"},
					},
				},
			},
			port:            5432,
			protocol:        "tcp",
			srcIP:           "10.0.1.5",
			expectedAllowed: true,
			expectedCIDR:    "0.0.0.0/0",
		},
		{
			name: "rule matches source IP in CIDR",
			sgs: []SecurityGroup{
				{
					ID:   "sg-001",
					Name: "internal-sg",
					Rules: []SGRule{
						{Direction: "inbound", Protocol: "tcp",
							FromPort: 5432, ToPort: 5432, CIDR: "10.0.0.0/8"},
					},
				},
			},
			port:            5432,
			protocol:        "tcp",
			srcIP:           "10.0.1.45",
			expectedAllowed: true,
			expectedCIDR:    "10.0.0.0/8",
		},
		{
			name: "source IP outside rule CIDR — denied",
			sgs: []SecurityGroup{
				{
					ID:   "sg-001",
					Name: "internal-sg",
					Rules: []SGRule{
						{Direction: "inbound", Protocol: "tcp",
							FromPort: 5432, ToPort: 5432, CIDR: "10.0.0.0/8"},
					},
				},
			},
			port:            5432,
			protocol:        "tcp",
			srcIP:           "203.0.113.5",
			expectedAllowed: false,
		},
		{
			name: "outbound rules ignored in inbound evaluation",
			sgs: []SecurityGroup{
				{
					ID:   "sg-001",
					Name: "web-sg",
					Rules: []SGRule{
						{Direction: "outbound", Protocol: "-1",
							FromPort: 0, ToPort: 0, CIDR: "0.0.0.0/0"},
					},
				},
			},
			port:            443,
			protocol:        "tcp",
			srcIP:           "0.0.0.0/0",
			expectedAllowed: false,
		},
		{
			name: "rule in second SG allows traffic — any SG match is sufficient",
			sgs: []SecurityGroup{
				{
					ID:   "sg-001",
					Name: "web-sg",
					Rules: []SGRule{
						{Direction: "inbound", Protocol: "tcp",
							FromPort: 80, ToPort: 80, CIDR: "0.0.0.0/0"},
					},
				},
				{
					ID:   "sg-002",
					Name: "https-sg",
					Rules: []SGRule{
						{Direction: "inbound", Protocol: "tcp",
							FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0"},
					},
				},
			},
			port:            443,
			protocol:        "tcp",
			srcIP:           "203.0.113.5",
			expectedAllowed: true,
			expectedCIDR:    "0.0.0.0/0",
		},
		{
			name:            "empty security groups — implicit deny",
			sgs:             []SecurityGroup{},
			port:            443,
			protocol:        "tcp",
			srcIP:           "0.0.0.0/0",
			expectedAllowed: false,
		},
		{
			name: "port range — port inside range",
			sgs: []SecurityGroup{
				{
					ID:   "sg-001",
					Name: "range-sg",
					Rules: []SGRule{
						{Direction: "inbound", Protocol: "tcp",
							FromPort: 8000, ToPort: 9000, CIDR: "0.0.0.0/0"},
					},
				},
			},
			port:            8080,
			protocol:        "tcp",
			srcIP:           "0.0.0.0/0",
			expectedAllowed: true,
			expectedCIDR:    "0.0.0.0/0",
		},
		{
			name: "wrong protocol — tcp rule does not match udp request",
			sgs: []SecurityGroup{
				{
					ID:   "sg-001",
					Name: "web-sg",
					Rules: []SGRule{
						{Direction: "inbound", Protocol: "tcp",
							FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0"},
					},
				},
			},
			port:            443,
			protocol:        "udp",
			srcIP:           "0.0.0.0/0",
			expectedAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, allowed := EvaluateSG(tt.sgs, tt.port, tt.protocol, tt.srcIP)

			if allowed != tt.expectedAllowed {
				t.Errorf("EvaluateSG() allowed = %v, want %v", allowed, tt.expectedAllowed)
			}

			if allowed && rule.CIDR != tt.expectedCIDR {
				t.Errorf("EvaluateSG() matched rule CIDR = %q, want %q",
					rule.CIDR, tt.expectedCIDR)
			}
		})
	}
}

func TestSGProtocolMatches(t *testing.T) {
	tests := []struct {
		name              string
		ruleProtocol      string
		requestedProtocol string
		expected          bool
	}{
		{"all protocol matches tcp", "-1", "tcp", true},
		{"all protocol matches udp", "-1", "udp", true},
		{"tcp matches tcp", "tcp", "tcp", true},
		{"tcp does not match udp", "tcp", "udp", false},
		{"udp matches udp", "udp", "udp", true},
		{"udp does not match tcp", "udp", "tcp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sgProtocolMatches(tt.ruleProtocol, tt.requestedProtocol)
			if got != tt.expected {
				t.Errorf("sgProtocolMatches(%q, %q) = %v, want %v",
					tt.ruleProtocol, tt.requestedProtocol, got, tt.expected)
			}
		})
	}
}

func TestMapSGRules(t *testing.T) {
	tests := []struct {
		name          string
		permission    types.IpPermission
		direction     string
		expectedCount int
		expectedCIDRs []string
	}{
		{
			name: "single IPv4 CIDR expands to one rule",
			permission: types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				IpRanges: []types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
			direction:     "inbound",
			expectedCount: 1,
			expectedCIDRs: []string{"0.0.0.0/0"},
		},
		{
			name: "multiple IPv4 CIDRs expand to multiple rules",
			permission: types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges: []types.IpRange{
					{CidrIp: aws.String("10.0.0.0/8")},
					{CidrIp: aws.String("203.0.113.0/24")},
				},
			},
			direction:     "inbound",
			expectedCount: 2,
			expectedCIDRs: []string{"10.0.0.0/8", "203.0.113.0/24"},
		},
		{
			name: "all traffic rule — no port range",
			permission: types.IpPermission{
				IpProtocol: aws.String("-1"),
				IpRanges: []types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
			direction:     "inbound",
			expectedCount: 1,
			expectedCIDRs: []string{"0.0.0.0/0"},
		},
		{
			name: "no CIDRs — empty rules",
			permission: types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				IpRanges:   []types.IpRange{},
			},
			direction:     "inbound",
			expectedCount: 0,
			expectedCIDRs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapSGRules(tt.permission, tt.direction)

			if len(got) != tt.expectedCount {
				t.Errorf("mapSGRules() count = %d, want %d", len(got), tt.expectedCount)
				return
			}

			for i, cidr := range tt.expectedCIDRs {
				if got[i].CIDR != cidr {
					t.Errorf("rule[%d].CIDR = %q, want %q", i, got[i].CIDR, cidr)
				}
			}
		})
	}
}
