package aws

import "context"

// AWSClient defines all AWS API operations whyblock needs.
// This interface exists so commands can be tested with mock clients.
type AWSClient interface {
	GetInstance(ctx context.Context, instanceID string) (InstanceData, error)
	GetSecurityGroups(ctx context.Context, sgIDs []string) ([]SecurityGroup, error)
	GetNACL(ctx context.Context, subnetID string) (NACL, error)
	GetRouteTable(ctx context.Context, subnetID string) (RouteTable, error)
	GetIGW(ctx context.Context, vpcID string) (IGW, error)
	GetEIP(ctx context.Context, instanceID string) (string, error)
	ValidatePermissions(ctx context.Context) ([]string, error) // returns missing permissions
}

// InstanceData is the raw data returned from AWS for an EC2 instance.
type InstanceData struct {
	InstanceID     string
	PublicIP       string
	PrivateIP      string
	VPCID          string
	SubnetID       string
	SecurityGroups []string
	State          string
}

// SecurityGroup holds inbound and outbound rules for one SG.
type SecurityGroup struct {
	ID    string
	Name  string
	Rules []SGRule
}

// SGRule is a single Security Group rule.
type SGRule struct {
	Direction string // inbound | outbound
	Protocol  string
	FromPort  int
	ToPort    int
	CIDR      string
}

// NACLRule is a single NACL rule entry.
type NACLRule struct {
	RuleNumber int
	Direction  string // inbound | outbound
	Protocol   string
	FromPort   int
	ToPort     int
	CIDR       string
	Action     string // ALLOW | DENY
}

// NACL holds all rules for a Network ACL.
type NACL struct {
	ID    string
	Rules []NACLRule
}

// RouteTable holds the routes for a subnet's route table.
type RouteTable struct {
	ID     string
	Routes []Route
}

// Route is a single entry in a route table.
type Route struct {
	Destination string // e.g. 0.0.0.0/0
	Target      string // e.g. igw-0abc123 or local
}

// IGW holds Internet Gateway info.
type IGW struct {
	ID       string
	Attached bool
}
