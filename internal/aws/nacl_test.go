package aws

import (
	"testing"
)

// testNACL builds a NACL with the given inbound rules for testing.
func testNACL(rules []NACLRule) NACL {
	return NACL{
		ID:    "acl-0abc123",
		Rules: rules,
	}
}

func TestEvaluateNACL(t *testing.T) {
	tests := []struct {
		name           string
		nacl           NACL
		port           int
		protocol       string
		srcIP          string
		expectedAction string
		expectedRule   int
	}{
		{
			name: "port allowed by first rule",
			nacl: testNACL([]NACLRule{
				{RuleNumber: 100, Direction: "inbound", Protocol: "6",
					FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0", Action: "ALLOW"},
				{RuleNumber: 200, Direction: "inbound", Protocol: "6",
					FromPort: 80, ToPort: 80, CIDR: "0.0.0.0/0", Action: "ALLOW"},
			}),
			port:           443,
			protocol:       "tcp",
			srcIP:          "0.0.0.0/0",
			expectedAction: "ALLOW",
			expectedRule:   100,
		},
		{
			name: "port explicitly denied before allow rule",
			nacl: testNACL([]NACLRule{
				{RuleNumber: 100, Direction: "inbound", Protocol: "6",
					FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0", Action: "DENY"},
				{RuleNumber: 200, Direction: "inbound", Protocol: "-1",
					FromPort: 0, ToPort: 0, CIDR: "0.0.0.0/0", Action: "ALLOW"},
			}),
			port:           443,
			protocol:       "tcp",
			srcIP:          "0.0.0.0/0",
			expectedAction: "DENY",
			expectedRule:   100,
		},
		{
			name: "no matching rule — implicit deny",
			nacl: testNACL([]NACLRule{
				{RuleNumber: 100, Direction: "inbound", Protocol: "6",
					FromPort: 80, ToPort: 80, CIDR: "0.0.0.0/0", Action: "ALLOW"},
			}),
			port:           443,
			protocol:       "tcp",
			srcIP:          "0.0.0.0/0",
			expectedAction: "DENY",
			expectedRule:   naclWildcardRuleNumber,
		},
		{
			name: "all-traffic rule allows all ports",
			nacl: testNACL([]NACLRule{
				{RuleNumber: 100, Direction: "inbound", Protocol: "-1",
					FromPort: 0, ToPort: 0, CIDR: "0.0.0.0/0", Action: "ALLOW"},
			}),
			port:           5432,
			protocol:       "tcp",
			srcIP:          "203.0.113.5",
			expectedAction: "ALLOW",
			expectedRule:   100,
		},
		{
			name: "rule allows port range — port inside range",
			nacl: testNACL([]NACLRule{
				{RuleNumber: 100, Direction: "inbound", Protocol: "6",
					FromPort: 1024, ToPort: 65535, CIDR: "0.0.0.0/0", Action: "ALLOW"},
			}),
			port:           8080,
			protocol:       "tcp",
			srcIP:          "0.0.0.0/0",
			expectedAction: "ALLOW",
			expectedRule:   100,
		},
		{
			name: "rule allows port range — port outside range",
			nacl: testNACL([]NACLRule{
				{RuleNumber: 100, Direction: "inbound", Protocol: "6",
					FromPort: 1024, ToPort: 65535, CIDR: "0.0.0.0/0", Action: "ALLOW"},
			}),
			port:           80,
			protocol:       "tcp",
			srcIP:          "0.0.0.0/0",
			expectedAction: "DENY",
			expectedRule:   naclWildcardRuleNumber,
		},
		{
			name: "source IP outside rule CIDR — no match",
			nacl: testNACL([]NACLRule{
				{RuleNumber: 100, Direction: "inbound", Protocol: "6",
					FromPort: 443, ToPort: 443, CIDR: "10.0.0.0/8", Action: "ALLOW"},
			}),
			port:           443,
			protocol:       "tcp",
			srcIP:          "203.0.113.5",
			expectedAction: "DENY",
			expectedRule:   naclWildcardRuleNumber,
		},
		{
			name: "outbound rules ignored in inbound evaluation",
			nacl: testNACL([]NACLRule{
				{RuleNumber: 100, Direction: "outbound", Protocol: "-1",
					FromPort: 0, ToPort: 0, CIDR: "0.0.0.0/0", Action: "ALLOW"},
			}),
			port:           443,
			protocol:       "tcp",
			srcIP:          "0.0.0.0/0",
			expectedAction: "DENY",
			expectedRule:   naclWildcardRuleNumber,
		},
		{
			name: "rules evaluated in number order not slice order",
			nacl: testNACL([]NACLRule{
				// intentionally out of order in slice
				{RuleNumber: 200, Direction: "inbound", Protocol: "6",
					FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0", Action: "ALLOW"},
				{RuleNumber: 100, Direction: "inbound", Protocol: "6",
					FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0", Action: "DENY"},
			}),
			port:           443,
			protocol:       "tcp",
			srcIP:          "0.0.0.0/0",
			expectedAction: "DENY", // rule 100 wins even though it's second in slice
			expectedRule:   100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, matched := EvaluateNACL(tt.nacl, tt.port, tt.protocol, tt.srcIP)

			if !matched {
				t.Fatal("EvaluateNACL() matched = false, want true")
			}
			if rule.Action != tt.expectedAction {
				t.Errorf("Action = %q, want %q", rule.Action, tt.expectedAction)
			}
			if rule.RuleNumber != tt.expectedRule {
				t.Errorf("RuleNumber = %d, want %d", rule.RuleNumber, tt.expectedRule)
			}
		})
	}
}

func TestProtocolMatches(t *testing.T) {
	tests := []struct {
		name              string
		ruleProtocol      string
		requestedProtocol string
		expected          bool
	}{
		{"all protocol matches tcp", "-1", "tcp", true},
		{"all protocol matches udp", "-1", "udp", true},
		{"tcp number matches tcp", "6", "tcp", true},
		{"tcp number does not match udp", "6", "udp", false},
		{"udp number matches udp", "17", "udp", true},
		{"udp number does not match tcp", "17", "tcp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocolMatches(tt.ruleProtocol, tt.requestedProtocol)
			if got != tt.expected {
				t.Errorf("protocolMatches(%q, %q) = %v, want %v",
					tt.ruleProtocol, tt.requestedProtocol, got, tt.expected)
			}
		})
	}
}

func TestPortInRange(t *testing.T) {
	tests := []struct {
		name     string
		port     int
		from     int
		to       int
		expected bool
	}{
		{"exact match", 443, 443, 443, true},
		{"inside range", 8080, 1024, 65535, true},
		{"below range", 80, 1024, 65535, false},
		{"above range", 70000, 1024, 65535, false},
		{"all ports — from=0 to=0", 443, 0, 0, true},
		{"lower boundary", 1024, 1024, 65535, true},
		{"upper boundary", 65535, 1024, 65535, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := portInRange(tt.port, tt.from, tt.to)
			if got != tt.expected {
				t.Errorf("portInRange(%d, %d, %d) = %v, want %v",
					tt.port, tt.from, tt.to, got, tt.expected)
			}
		})
	}
}

func TestIPInCIDR(t *testing.T) {
	tests := []struct {
		name     string
		srcIP    string
		cidr     string
		expected bool
	}{
		{"0.0.0.0/0 matches any IP", "203.0.113.5", "0.0.0.0/0", true},
		{"IP inside subnet", "10.0.1.5", "10.0.0.0/8", true},
		{"IP outside subnet", "192.168.1.1", "10.0.0.0/8", false},
		{"exact IP match as /32", "203.0.113.5", "203.0.113.5/32", true},
		{"different IP in /32", "203.0.113.6", "203.0.113.5/32", false},
		{"CIDR source inside rule CIDR", "10.0.1.0/24", "10.0.0.0/8", true},
		{"CIDR source outside rule CIDR", "192.168.0.0/24", "10.0.0.0/8", false},
		{"invalid source IP", "not-an-ip", "10.0.0.0/8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipInCIDR(tt.srcIP, tt.cidr)
			if got != tt.expected {
				t.Errorf("ipInCIDR(%q, %q) = %v, want %v",
					tt.srcIP, tt.cidr, got, tt.expected)
			}
		})
	}
}
