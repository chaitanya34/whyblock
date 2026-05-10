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

const (
	// defaultRoute is the IPv4 default route CIDR
	defaultRoute = "0.0.0.0/0"

	// localRoute is the VPC-internal route present in every route table
	localRoute = "local"
)

// GetRouteTable fetches the route table associated with the given subnet.
// Every subnet in AWS is associated with exactly one route table —
// either explicitly or implicitly via the VPC's main route table.
func (c *Client) GetRouteTable(ctx context.Context, subnetID string) (RouteTable, error) {
	// first try: find a route table explicitly associated with this subnet
	rt, err := c.describeRouteTable(ctx, "association.subnet-id", subnetID)
	if err != nil {
		return RouteTable{}, err
	}

	// if no explicit association found, fall back to the VPC main route table
	// AWS implicitly associates subnets with the main route table when no
	// explicit association exists
	if rt == nil {
		instance, err := c.getSubnetVPCID(ctx, subnetID)
		if err != nil {
			return RouteTable{}, err
		}

		rt, err = c.describeRouteTable(ctx, "association.main", "true")
		if err != nil {
			return RouteTable{}, err
		}

		// filter to only the main route table belonging to this VPC
		if rt != nil {
			vpcRT, err := c.getMainRouteTableForVPC(ctx, instance)
			if err != nil {
				return RouteTable{}, err
			}
			rt = vpcRT
		}
	}

	if rt == nil {
		return RouteTable{}, fmt.Errorf("no route table found for subnet %s", subnetID)
	}

	return *rt, nil
}

// describeRouteTable is a helper that fetches route tables by a filter.
// Returns nil if no route table matches the filter (not an error).
func (c *Client) describeRouteTable(
	ctx context.Context,
	filterName string,
	filterValue string,
) (*RouteTable, error) {
	input := &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String(filterName),
				Values: []string{filterValue},
			},
		},
	}

	resp, err := c.ec2Client.DescribeRouteTables(ctx, input)
	if err != nil {
		return nil, mapRouteTableError(err)
	}

	if len(resp.RouteTables) == 0 {
		return nil, nil
	}

	return mapRouteTable(resp.RouteTables[0]), nil
}

// getMainRouteTableForVPC fetches the main route table for a VPC.
func (c *Client) getMainRouteTableForVPC(ctx context.Context, vpcID string) (*RouteTable, error) {
	input := &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []string{vpcID},
			},
			{
				Name:   aws.String("association.main"),
				Values: []string{"true"},
			},
		},
	}

	resp, err := c.ec2Client.DescribeRouteTables(ctx, input)
	if err != nil {
		return nil, mapRouteTableError(err)
	}

	if len(resp.RouteTables) == 0 {
		return nil, nil
	}
	// Why only one main route table? AWS guarantees exactly one main route table per VPC.
	return mapRouteTable(resp.RouteTables[0]), nil
}

// getSubnetVPCID fetches the VPC ID for a subnet.
// Needed when falling back to the main route table.
func (c *Client) getSubnetVPCID(ctx context.Context, subnetID string) (string, error) {
	input := &ec2.DescribeSubnetsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("subnet-id"),
				Values: []string{subnetID},
			},
		},
	}

	resp, err := c.ec2Client.DescribeSubnets(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to describe subnet %s: %w", subnetID, err)
	}

	if len(resp.Subnets) == 0 {
		return "", fmt.Errorf("subnet %s not found", subnetID)
	}

	// Why again single subnet? We asked for one specific subnet ID, so we expect exactly one result.
	return aws.ToString(resp.Subnets[0].VpcId), nil
}

// mapRouteTable converts the AWS SDK route table type into our internal type.
// Only maps active routes — blackhole routes are skipped.
func mapRouteTable(rt types.RouteTable) *RouteTable {
	result := &RouteTable{
		ID:     aws.ToString(rt.RouteTableId),
		Routes: make([]Route, 0, len(rt.Routes)),
	}

	for _, r := range rt.Routes {
		// skip blackhole routes — these point to deleted resources
		// and are not useful for connectivity analysis
		if r.State == types.RouteStateBlackhole {
			continue
		}

		route := Route{
			Destination: resolveDestination(r),
			Target:      resolveTarget(r),
		}

		// skip routes with no destination — malformed entries
		if route.Destination == "" {
			continue
		}

		result.Routes = append(result.Routes, route)
	}

	return result
}

// HasDefaultRoute checks if the route table has a 0.0.0.0/0 route
// pointing to an Internet Gateway.
// This is Layer 3 of the connectivity check.
func HasDefaultRoute(rt RouteTable) (bool, string) {
	for _, route := range rt.Routes {
		if route.Destination == defaultRoute {
			return true, route.Target
		}
	}
	return false, ""
}

// resolveDestination extracts the destination CIDR from a route.
// AWS SDK uses separate fields for IPv4 and IPv6 destinations.
func resolveDestination(r types.Route) string {
	if r.DestinationCidrBlock != nil {
		return aws.ToString(r.DestinationCidrBlock)
	}
	if r.DestinationIpv6CidrBlock != nil {
		return aws.ToString(r.DestinationIpv6CidrBlock)
	}
	return ""
}

// resolveTarget extracts the human-readable target from a route.
// AWS SDK uses separate fields for each possible target type
// (IGW, NAT GW, VPC peering, transit GW etc.).
func resolveTarget(r types.Route) string {
	switch {
	case r.GatewayId != nil:
		return aws.ToString(r.GatewayId) // igw-xxx or "local"
	case r.NatGatewayId != nil:
		return aws.ToString(r.NatGatewayId) // nat-xxx
	case r.TransitGatewayId != nil:
		return aws.ToString(r.TransitGatewayId) // tgw-xxx
	case r.VpcPeeringConnectionId != nil:
		return aws.ToString(r.VpcPeeringConnectionId) // pcx-xxx
	case r.NetworkInterfaceId != nil:
		return aws.ToString(r.NetworkInterfaceId) // eni-xxx
	case r.InstanceId != nil:
		return aws.ToString(r.InstanceId) // i-xxx (for NAT instances)
	default:
		return "unknown"
	}
}

// mapRouteTableError converts AWS API errors into clear user-facing messages.
func mapRouteTableError(err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if isAccessDenied(err) {
			return fmt.Errorf("permission denied — missing ec2:DescribeRouteTables")
		}
	}
	return fmt.Errorf("failed to describe route table: %w", err)
}
