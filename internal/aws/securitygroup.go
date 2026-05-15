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

// GetSecurityGroups fetches all security groups attached to an instance.
// Multiple SGs can be attached — all of them are evaluated together.
func (c *Client) GetSecurityGroups(ctx context.Context, sgIDs []string) ([]SecurityGroup, error) {
	if len(sgIDs) == 0 {
		return []SecurityGroup{}, nil
	}

	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: sgIDs,
	}

	resp, err := c.ec2Client.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, mapSGError(err)
	}

	result := make([]SecurityGroup, 0, len(resp.SecurityGroups))
	for _, sg := range resp.SecurityGroups {
		result = append(result, mapSecurityGroup(sg))
	}

	return result, nil
}

// EvaluateSG checks whether any inbound rule across all attached security
// groups permits the given port, protocol, and source IP.
//
// Security Groups are stateful and use allow-only rules.
// All rules across all attached SGs are evaluated together —
// if ANY rule permits the traffic, it is allowed.
// There is no rule ordering and no explicit DENY — only implicit deny
// when no rule matches.
//
// Returns the matching SGRule and true if allowed, zero value and false
// if no rule permits the traffic.
func EvaluateSG(sgs []SecurityGroup, port int, protocol string, srcIP string) (SGRule, bool) {
	for _, sg := range sgs {
		for _, rule := range sg.Rules {
			if rule.Direction != "inbound" {
				continue
			}
			if sgRuleMatches(rule, port, protocol, srcIP) {
				return rule, true
			}
		}
	}
	return SGRule{}, false
}

// sgRuleMatches checks whether a single SG rule permits the traffic.
func sgRuleMatches(rule SGRule, port int, protocol string, srcIP string) bool {
	if !sgProtocolMatches(rule.Protocol, protocol) {
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

// sgProtocolMatches checks if an SG rule protocol covers the requested protocol.
// Security Groups use "-1" for all traffic, "tcp", "udp" as strings
// unlike NACLs which use protocol numbers.
func sgProtocolMatches(ruleProtocol, requestedProtocol string) bool {
	// -1 means all traffic
	if ruleProtocol == protocolAll {
		return true
	}
	return ruleProtocol == requestedProtocol
}

// mapSecurityGroup converts the AWS SDK SG type into our internal type.
func mapSecurityGroup(sg types.SecurityGroup) SecurityGroup {
	result := SecurityGroup{
		ID:    aws.ToString(sg.GroupId),
		Name:  aws.ToString(sg.GroupName),
		Rules: make([]SGRule, 0),
	}

	// map inbound rules
	for _, p := range sg.IpPermissions {
		rules := mapSGRules(p, "inbound")
		result.Rules = append(result.Rules, rules...)
	}

	// map outbound rules
	for _, p := range sg.IpPermissionsEgress {
		rules := mapSGRules(p, "outbound")
		result.Rules = append(result.Rules, rules...)
	}

	return result
}

// mapSGRules converts a single IpPermission into one or more SGRules.
// One IpPermission can contain multiple CIDR ranges — we expand them
// into individual rules for simpler evaluation logic.
func mapSGRules(p types.IpPermission, direction string) []SGRule {
	rules := make([]SGRule, 0)

	protocol := aws.ToString(p.IpProtocol)

	fromPort := 0
	toPort := 0

	// port range is only set for TCP and UDP rules
	// all-traffic rules (-1) have no port range in AWS response
	if p.FromPort != nil {
		fromPort = int(aws.ToInt32(p.FromPort))
	}
	if p.ToPort != nil {
		toPort = int(aws.ToInt32(p.ToPort))
	}

	// expand IPv4 CIDR ranges into individual rules
	for _, r := range p.IpRanges {
		rules = append(rules, SGRule{
			Direction: direction,
			Protocol:  protocol,
			FromPort:  fromPort,
			ToPort:    toPort,
			CIDR:      aws.ToString(r.CidrIp),
		})
	}

	// expand IPv6 CIDR ranges into individual rules
	for _, r := range p.Ipv6Ranges {
		rules = append(rules, SGRule{
			Direction: direction,
			Protocol:  protocol,
			FromPort:  fromPort,
			ToPort:    toPort,
			CIDR:      aws.ToString(r.CidrIpv6),
		})
	}

	return rules
}

// mapSGError converts AWS API errors into clear user-facing messages.
func mapSGError(err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "InvalidGroup.NotFound":
			return fmt.Errorf("one or more security groups not found — " +
				"they may have been deleted or belong to a different region")
		}
		if isAccessDenied(err) {
			return fmt.Errorf("permission denied — missing ec2:DescribeSecurityGroups")
		}
	}
	return fmt.Errorf("failed to describe security groups: %w", err)
}
