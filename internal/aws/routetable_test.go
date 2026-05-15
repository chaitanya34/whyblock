package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestHasDefaultRoute(t *testing.T) {
	tests := []struct {
		name           string
		routeTable     RouteTable
		expectedFound  bool
		expectedTarget string
	}{
		{
			name: "default route pointing to IGW",
			routeTable: RouteTable{
				ID: "rtb-0abc123",
				Routes: []Route{
					{Destination: "10.0.0.0/16", Target: "local"},
					{Destination: "0.0.0.0/0", Target: "igw-0abc123"},
				},
			},
			expectedFound:  true,
			expectedTarget: "igw-0abc123",
		},
		{
			name: "default route pointing to NAT gateway — private subnet",
			routeTable: RouteTable{
				ID: "rtb-0abc123",
				Routes: []Route{
					{Destination: "10.0.0.0/16", Target: "local"},
					{Destination: "0.0.0.0/0", Target: "nat-0abc123"},
				},
			},
			expectedFound:  true,
			expectedTarget: "nat-0abc123",
		},
		{
			name: "no default route — fully private subnet",
			routeTable: RouteTable{
				ID: "rtb-0abc123",
				Routes: []Route{
					{Destination: "10.0.0.0/16", Target: "local"},
				},
			},
			expectedFound:  false,
			expectedTarget: "",
		},
		{
			name:           "empty route table",
			routeTable:     RouteTable{ID: "rtb-0abc123", Routes: []Route{}},
			expectedFound:  false,
			expectedTarget: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, target := HasDefaultRoute(tt.routeTable)

			if found != tt.expectedFound {
				t.Errorf("HasDefaultRoute() found = %v, want %v", found, tt.expectedFound)
			}
			if target != tt.expectedTarget {
				t.Errorf("HasDefaultRoute() target = %q, want %q", target, tt.expectedTarget)
			}
		})
	}
}

func TestResolveDestination(t *testing.T) {
	tests := []struct {
		name     string
		route    types.Route
		expected string
	}{
		{
			name:     "IPv4 CIDR",
			route:    types.Route{DestinationCidrBlock: aws.String("0.0.0.0/0")},
			expected: "0.0.0.0/0",
		},
		{
			name:     "IPv6 CIDR",
			route:    types.Route{DestinationIpv6CidrBlock: aws.String("::/0")},
			expected: "::/0",
		},
		{
			name:     "no destination",
			route:    types.Route{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveDestination(tt.route)
			if got != tt.expected {
				t.Errorf("resolveDestination() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestResolveTarget(t *testing.T) {
	tests := []struct {
		name     string
		route    types.Route
		expected string
	}{
		{
			name:     "internet gateway",
			route:    types.Route{GatewayId: aws.String("igw-0abc123")},
			expected: "igw-0abc123",
		},
		{
			name:     "local route",
			route:    types.Route{GatewayId: aws.String("local")},
			expected: "local",
		},
		{
			name:     "NAT gateway",
			route:    types.Route{NatGatewayId: aws.String("nat-0abc123")},
			expected: "nat-0abc123",
		},
		{
			name:     "transit gateway",
			route:    types.Route{TransitGatewayId: aws.String("tgw-0abc123")},
			expected: "tgw-0abc123",
		},
		{
			name:     "VPC peering",
			route:    types.Route{VpcPeeringConnectionId: aws.String("pcx-0abc123")},
			expected: "pcx-0abc123",
		},
		{
			name:     "no target fields set",
			route:    types.Route{},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveTarget(tt.route)
			if got != tt.expected {
				t.Errorf("resolveTarget() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestMapRouteTable(t *testing.T) {
	tests := []struct {
		name           string
		input          types.RouteTable
		expectedRoutes int
	}{
		{
			name: "active routes mapped correctly",
			input: types.RouteTable{
				RouteTableId: aws.String("rtb-0abc123"),
				Routes: []types.Route{
					{
						DestinationCidrBlock: aws.String("10.0.0.0/16"),
						GatewayId:            aws.String("local"),
						State:                types.RouteStateActive,
					},
					{
						DestinationCidrBlock: aws.String("0.0.0.0/0"),
						GatewayId:            aws.String("igw-0abc123"),
						State:                types.RouteStateActive,
					},
				},
			},
			expectedRoutes: 2,
		},
		{
			name: "blackhole routes excluded",
			input: types.RouteTable{
				RouteTableId: aws.String("rtb-0abc123"),
				Routes: []types.Route{
					{
						DestinationCidrBlock: aws.String("10.0.0.0/16"),
						GatewayId:            aws.String("local"),
						State:                types.RouteStateActive,
					},
					{
						DestinationCidrBlock: aws.String("0.0.0.0/0"),
						NatGatewayId:         aws.String("nat-deleted"),
						State:                types.RouteStateBlackhole,
					},
				},
			},
			expectedRoutes: 1, // blackhole excluded
		},
		{
			name: "routes with no destination excluded",
			input: types.RouteTable{
				RouteTableId: aws.String("rtb-0abc123"),
				Routes: []types.Route{
					{
						GatewayId: aws.String("igw-0abc123"),
						State:     types.RouteStateActive,
						// no DestinationCidrBlock set — malformed
					},
				},
			},
			expectedRoutes: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapRouteTable(tt.input)
			if len(got.Routes) != tt.expectedRoutes {
				t.Errorf("mapRouteTable() routes count = %d, want %d",
					len(got.Routes), tt.expectedRoutes)
			}
		})
	}
}
