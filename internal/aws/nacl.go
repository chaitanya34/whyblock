package aws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

const (
	// protocolAll represents the AWS wildcard protocol (-1)
	protocolAll = "-1"

	// protocolTCP is the AWS protocol number for TCP
	protocolTCP = "6"

	// protocolUDP is the AWS protocol number for UDP
	protocolUDP = "17"

	// naclWildcardRuleNumber is the implicit deny rule AWS adds to every NACL
	naclWildcardRuleNumber = 32767
)

// GetNACL fetches the Network ACL associated with the given subnet.
func (c *Client) GetNACL(ctx context.Context, subnetID string) (NACL, error) {
	input := &ec2.DescribeNetworkAclsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("association.subnet-id"),
				Values: []string{subnetID},
			},
		},
	}

	resp, err := c.ec2Client.DescribeNetworkAcls(ctx, input)
	if err != nil {
		return NACL{}, mapNACLError(err, subnetID)
	}

	if len(resp.NetworkAcls) == 0 {
		return NACL{}, fmt.Errorf("no NACL found for subnet %s", subnetID)
	}

	return mapNACL(resp.NetworkAcls[0]), nil
}

// EvaluateNACL evaluates inbound NACL rules against a given port, protocol,
// and source IP. Rules are evaluated in ascending rule-number order.
// First matching rule wins — ALLOW or DENY.
// If no rule matches, the implicit deny applies.
//
// This is the core stateless firewall logic for Layer 4.
func EvaluateNACL(nacl NACL, port int, protocol string, srcIP string) (NACLRule, bool) {
	// collect only inbound rules, excluding the wildcard implicit deny
	// we handle implicit deny ourselves at the end
	inbound := make([]NACLRule, 0)
	for _, rule := range nacl.Rules {
		if rule.Direction == "inbound" && rule.RuleNumber != naclWildcardRuleNumber {
			inbound = append(inbound, rule)
		}
	}

	// sort ascending by rule number — this is what AWS does
	sort.Slice(inbound, func(i, j int) bool {
		return inbound[i].RuleNumber < inbound[j].RuleNumber
	})

	for _, rule := range inbound {
		if ruleMatches(rule, port, protocol, srcIP) {
			return rule, true
		}
	}

	// no rule matched — implicit deny
	// return a synthetic rule representing the implicit deny
	return NACLRule{
		RuleNumber: naclWildcardRuleNumber,
		Direction:  "inbound",
		Action:     "deny",
		CIDR:       "0.0.0.0/0",
		Protocol:   protocolAll,
	}, true
}

// ruleMatches checks whether a single NACL rule applies to the given
// port, protocol, and source IP.
func ruleMatches(rule NACLRule, port int, protocol string, srcIP string) bool {
	if !protocolMatches(rule.Protocol, protocol) {
		return false
	}

	if !portInRange(port, rule.FromPort, rule.ToPort) {
		return false
	}

	if !ipInCIDR(srcIP, rule.CIDR) {
		return false
	}

	return true
}

// protocolMatches checks if a NACL rule protocol covers the requested protocol.
// AWS uses protocol numbers ("6"=TCP, "17"=UDP) and "-1" means all protocols.
func protocolMatches(ruleProtocol, requestedProtocol string) bool {
	// protocol -1 means ALL — matches everything
	if ruleProtocol == protocolAll {
		return true
	}

	switch requestedProtocol {
	case "tcp":
		return ruleProtocol == protocolTCP
	case "udp":
		return ruleProtocol == protocolUDP
	default:
		return ruleProtocol == requestedProtocol
	}
}

// portInRange checks whether a port falls within the rule's port range.
// When a NACL rule covers all protocols (-1), AWS sets FromPort and ToPort
// to 0. We treat 0-0 as "all ports".
func portInRange(port, from, to int) bool {
	// all-traffic rule: from=0 to=0 means all ports
	if from == 0 && to == 0 {
		return true
	}
	return port >= from && port <= to
}

// ipInCIDR checks whether a source IP falls within the rule's CIDR block.
// Handles the "internet" alias (0.0.0.0/0 matches everything).
func ipInCIDR(srcIP, cidr string) bool {
	// 0.0.0.0/0 matches all IPs
	if cidr == "0.0.0.0/0" {
		return true
	}

	// if srcIP is also a CIDR (e.g. user passed --from 10.0.0.0/24)
	// check if it is fully contained within the rule CIDR
	if _, srcNet, err := net.ParseCIDR(srcIP); err == nil {
		_, ruleNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return false
		}
		return ruleNet.Contains(srcNet.IP)
	}

	// srcIP is a plain IP address
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return false
	}

	_, ruleNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	return ruleNet.Contains(ip)
}

// mapNACL converts the AWS SDK NACL type into our internal NACL type.
func mapNACL(n types.NetworkAcl) NACL {
	nacl := NACL{
		ID:    aws.ToString(n.NetworkAclId),
		Rules: make([]NACLRule, 0, len(n.Entries)),
	}

	for _, entry := range n.Entries {
		rule := NACLRule{
			RuleNumber: int(aws.ToInt32(entry.RuleNumber)),
			Protocol:   aws.ToString(entry.Protocol),
			CIDR:       resolveCIDR(entry),
			Action:     string(entry.RuleAction),
		}

		// AWS uses Egress=false for inbound, Egress=true for outbound
		if aws.ToBool(entry.Egress) {
			rule.Direction = "outbound"
		} else {
			rule.Direction = "inbound"
		}

		// port range is only present for TCP/UDP rules
		// all-traffic rules (-1) have no port range
		if entry.PortRange != nil {
			rule.FromPort = int(aws.ToInt32(entry.PortRange.From))
			rule.ToPort = int(aws.ToInt32(entry.PortRange.To))
		}

		nacl.Rules = append(nacl.Rules, rule)
	}

	return nacl
}

// resolveCIDR extracts the CIDR from a NACL entry.
// AWS uses separate fields for IPv4 and IPv6.
func resolveCIDR(entry types.NetworkAclEntry) string {
	if entry.CidrBlock != nil {
		return aws.ToString(entry.CidrBlock)
	}
	if entry.Ipv6CidrBlock != nil {
		return aws.ToString(entry.Ipv6CidrBlock)
	}
	return ""
}

// mapNACLError converts AWS API errors into clear user-facing messages.
func mapNACLError(err error, subnetID string) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if isAccessDenied(err) {
			return fmt.Errorf("permission denied — missing ec2:DescribeNetworkAcls")
		}
	}
	return fmt.Errorf("failed to describe NACL for subnet %s: %w", subnetID, err)
}
