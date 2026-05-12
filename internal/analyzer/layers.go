package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/chaitanya34/whyblock/internal/aws"
	"github.com/chaitanya34/whyblock/internal/model"
)

// Layer 1 — public IP
// Layer 2 — IGW
// Layer 3 — route table
// Layer 4 — NACL evaluation (stateless, ordered)
// Layer 5 — security group evaluation (stateful, all rules)

const (
	layerPublicIP   = "Public IP"
	layerIGW        = "Internet Gateway"
	layerRouteTable = "Route Table"
	layerNACL       = "NACL Inbound"
	layerSG         = "Security Group"
)

// checkPublicIP is Layer 1.
// If the instance has no public IP, it is unreachable from the internet
// regardless of any other rule. This is the first gate.
func checkPublicIP(instance aws.InstanceData, eip string) model.LayerResult {
	// prefer EIP over auto-assigned public IP
	// EIP is shown first because it is the stable address
	publicIP := eip
	if publicIP == "" {
		publicIP = instance.PublicIP
	}

	if publicIP == "" {
		return model.LayerResult{
			Layer:   layerPublicIP,
			Detail:  "no public IP or Elastic IP assigned",
			Status:  model.StatusBlock,
			FixHint: "assign an Elastic IP or enable auto-assign public IP on the subnet",
		}
	}

	return model.LayerResult{
		Layer:  layerPublicIP,
		Detail: publicIP,
		Status: model.StatusAllow,
	}
}

// checkIGW is Layer 2.
// Even with a public IP, if no IGW is attached the VPC has no internet path.
func checkIGW(ctx context.Context, client aws.AWSClient, vpcID string) model.LayerResult {
	igw, err := client.GetIGW(ctx, vpcID)
	if err != nil {
		return errorLayer(layerIGW, err)
	}

	if !igw.Attached {
		return model.LayerResult{
			Layer:      layerIGW,
			Detail:     "no Internet Gateway attached to VPC",
			Status:     model.StatusBlock,
			FixHint:    "attach an Internet Gateway to the VPC",
			ConsoleURL: "https://console.aws.amazon.com/vpc/home#InternetGateways",
		}
	}

	return model.LayerResult{
		Layer:  layerIGW,
		Detail: fmt.Sprintf("%s attached to %s", igw.ID, vpcID),
		Status: model.StatusAllow,
	}
}

// checkRouteTable is Layer 3.
// The subnet must have a default route 0.0.0.0/0 pointing to the IGW.
// Without this, traffic has no path to the internet even if an IGW exists.
func checkRouteTable(
	ctx context.Context,
	client aws.AWSClient,
	subnetID string,
	region string,
) model.LayerResult {
	rt, err := client.GetRouteTable(ctx, subnetID)
	if err != nil {
		return errorLayer(layerRouteTable, err)
	}

	found, target := aws.HasDefaultRoute(rt)
	if !found {
		return model.LayerResult{
			Layer:   layerRouteTable,
			Detail:  fmt.Sprintf("no 0.0.0.0/0 route in %s", rt.ID),
			Status:  model.StatusBlock,
			FixHint: "add a 0.0.0.0/0 route pointing to the Internet Gateway",
			ConsoleURL: fmt.Sprintf(
				"https://console.aws.amazon.com/vpc/home?region=%s#RouteTables:routeTableId=%s",
				region, rt.ID,
			),
		}
	}

	// check if the default route points to an IGW
	// if it points to a NAT Gateway, instance is in a private subnet —
	// reachable from inside but NOT from the internet
	if !strings.HasPrefix(target, "igw-") {
		return model.LayerResult{
			Layer: layerRouteTable,
			Detail: fmt.Sprintf(
				"0.0.0.0/0 → %s (not an IGW — private subnet)",
				target,
			),
			Status:  model.StatusBlock,
			FixHint: "this is a private subnet — the default route points to a NAT Gateway, not an IGW. Instances in private subnets are not reachable from the internet",
		}
	}

	return model.LayerResult{
		Layer:  layerRouteTable,
		Detail: fmt.Sprintf("0.0.0.0/0 → %s", target),
		Status: model.StatusAllow,
	}
}

// checkNACL is Layer 4.
// NACLs are stateless and evaluated at the subnet boundary.
// Rules are evaluated in ascending rule number order — first match wins.
func checkNACL(
	ctx context.Context,
	client aws.AWSClient,
	subnetID string,
	port int,
	protocol string,
	srcIP string,
	region string,
) model.LayerResult {
	nacl, err := client.GetNACL(ctx, subnetID)
	if err != nil {
		return errorLayer(layerNACL, err)
	}

	rule, _ := aws.EvaluateNACL(nacl, port, protocol, srcIP)

	if rule.Action == "DENY" {
		detail := fmt.Sprintf("Rule %d: DENY %s", rule.RuleNumber, rule.CIDR)
		if rule.RuleNumber == 32767 {
			detail = "no matching rule — implicit DENY"
		}

		return model.LayerResult{
			Layer:   layerNACL,
			Detail:  detail,
			Status:  model.StatusBlock,
			FixHint: fmt.Sprintf("add an inbound ALLOW rule for %s port %d in the NACL", protocol, port),
			ConsoleURL: fmt.Sprintf(
				"https://console.aws.amazon.com/vpc/home?region=%s#NetworkAcls:networkAclId=%s",
				region, nacl.ID,
			),
		}
	}

	return model.LayerResult{
		Layer:  layerNACL,
		Detail: fmt.Sprintf("Rule %d: ALLOW %s", rule.RuleNumber, rule.CIDR),
		Status: model.StatusAllow,
	}
}

// checkSG is Layer 5.
// Security Groups are stateful and evaluated at the instance boundary.
// All rules across all attached SGs are evaluated — any match allows traffic.
func checkSG(
	ctx context.Context,
	client aws.AWSClient,
	sgIDs []string,
	port int,
	protocol string,
	srcIP string,
	region string,
) model.LayerResult {
	sgs, err := client.GetSecurityGroups(ctx, sgIDs)
	if err != nil {
		return errorLayer(layerSG, err)
	}

	rule, allowed := aws.EvaluateSG(sgs, port, protocol, srcIP)

	if !allowed {
		// collect what ports ARE allowed — helps the user understand
		// what the SG currently permits so they can see what's missing
		allowedPorts := collectAllowedPorts(sgs, protocol)

		detail := fmt.Sprintf("no rule permits %s:%d from %s", protocol, port, srcIP)
		if len(allowedPorts) > 0 {
			detail += fmt.Sprintf("\n  %s allows: %s", strings.Join(sgIDs, ", "), allowedPorts)
		}

		return model.LayerResult{
			Layer:      layerSG,
			Detail:     detail,
			Status:     model.StatusBlock,
			FixHint:    fmt.Sprintf("add inbound rule — %s port %d from %s", protocol, port, srcIP),
			ConsoleURL: buildSGConsoleURL(sgIDs, region),
		}
	}

	return model.LayerResult{
		Layer: layerSG,
		Detail: fmt.Sprintf(
			"%s: ALLOW %s:%d from %s",
			findSGID(sgs, rule), protocol, port, rule.CIDR,
		),
		Status: model.StatusAllow,
	}
}

// collectAllowedPorts builds a human-readable summary of currently
// allowed inbound ports for a given protocol across all SGs.
// Used in the blocked message to show the user what IS allowed.
func collectAllowedPorts(sgs []aws.SecurityGroup, protocol string) string {
	ports := make([]string, 0)
	seen := make(map[string]bool)

	for _, sg := range sgs {
		for _, rule := range sg.Rules {
			if rule.Direction != "inbound" {
				continue
			}
			if rule.Protocol != protocol && rule.Protocol != "-1" {
				continue
			}

			var entry string
			if rule.FromPort == rule.ToPort {
				entry = fmt.Sprintf("%d", rule.FromPort)
			} else {
				entry = fmt.Sprintf("%d-%d", rule.FromPort, rule.ToPort)
			}

			if !seen[entry] {
				seen[entry] = true
				ports = append(ports, entry)
			}
		}
	}

	if len(ports) == 0 {
		return "none"
	}

	return strings.Join(ports, ", ")
}

// findSGID returns the ID of the security group that contains the matching rule.
func findSGID(sgs []aws.SecurityGroup, rule aws.SGRule) string {
	for _, sg := range sgs {
		for _, r := range sg.Rules {
			if r.Direction == rule.Direction &&
				r.Protocol == rule.Protocol &&
				r.FromPort == rule.FromPort &&
				r.ToPort == rule.ToPort &&
				r.CIDR == rule.CIDR {
				return sg.ID
			}
		}
	}
	return "unknown-sg"
}

// buildSGConsoleURL returns a console deep link.
// If only one SG — link directly to it.
// If multiple — link to the SG list filtered by the instance's SGs.
func buildSGConsoleURL(sgIDs []string, region string) string {
	if len(sgIDs) == 1 {
		return fmt.Sprintf(
			"https://console.aws.amazon.com/ec2/v2/home?region=%s#SecurityGroups:groupId=%s",
			region, sgIDs[0],
		)
	}
	return fmt.Sprintf(
		"https://console.aws.amazon.com/ec2/v2/home?region=%s#SecurityGroups",
		region,
	)
}

// errorLayer creates a SKIPPED LayerResult when an AWS API call fails.
// We do not stop the entire check for API errors — we mark the layer
// as skipped and continue so the user gets partial results.
func errorLayer(layer string, err error) model.LayerResult {
	return model.LayerResult{
		Layer:  layer,
		Detail: fmt.Sprintf("API error: %s", err.Error()),
		Status: model.StatusSkipped,
	}
}
