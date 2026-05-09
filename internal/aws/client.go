package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/smithy-go"
)

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

// Client is the real aws client that implements AWSClient using the AWS SDK.
type Client struct {
	ec2Client *ec2.Client
	region    string // store region for constructing console URLs
}

// NewClient creates a new AWS client using the provided region and profile.
// It loads credentials from the standard AWS credential chain:
//   - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
//   - AWS config file (~/.aws/config)
//   - IAM role (if running on EC2/ECS)
func NewClient(ctx context.Context, region, profile string) (*Client, error) {
	// build option list dynamically
	// we only add options that the user actually provided
	opts := []func(*config.LoadOptions) error{}

	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	// load AWS config with the specified options
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	if cfg.Region == "" {
		return nil, fmt.Errorf("WS region not set — use --region flag or set AWS_DEFAULT_REGION")
	}

	client := ec2.NewFromConfig(cfg)
	return &Client{ec2Client: client, region: cfg.Region}, nil
}

// requiredPermissions is the list of IAM permissions whyblock needs.
var requiredPermissions = []string{
	"ec2:DescribeInstances",
	"ec2:DescribeSecurityGroups",
	"ec2:DescribeNetworkAcls",
	"ec2:DescribeRouteTables",
	"ec2:DescribeInternetGateways",
	"ec2:DescribeVpcs",
	"ec2:DescribeSubnets",
	"ec2:DescribeAddresses",
}

// ValidatePermissions checks that the caller has all required IAM permissions.
// Returns a list of missing permissions (empty slice means all good).
func (c *Client) ValidatePermissions(ctx context.Context) ([]string, error) {
	missingPermission := []string{}

	// for each required permission, do a dry-run API call
	// AWS dry-run returns a specific error if permission is missing
	// and a different specific error if permission exists (DryRunOperation)
	checks := map[string]func() error{
		"ec2:DescribeInstances": func() error {
			_, err := c.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{}, func(o *ec2.Options) { o.RetryMaxAttempts = 1 })
			return err
		},
		"ec2:DescribeSecurityGroups": func() error {
			_, err := c.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{}, func(o *ec2.Options) { o.RetryMaxAttempts = 1 })
			return err
		},
		"ec2:DescribeNetworkAcls": func() error {
			_, err := c.ec2Client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{}, func(o *ec2.Options) { o.RetryMaxAttempts = 1 })
			return err
		},
		"ec2:DescribeRouteTables": func() error {
			_, err := c.ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{}, func(o *ec2.Options) { o.RetryMaxAttempts = 1 })
			return err
		},
		"ec2:DescribeInternetGateways": func() error {
			_, err := c.ec2Client.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{}, func(o *ec2.Options) { o.RetryMaxAttempts = 1 })
			return err
		},
		"ec2:DescribeVpcs": func() error {
			_, err := c.ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{}, func(o *ec2.Options) { o.RetryMaxAttempts = 1 })
			return err
		},
		"ec2:DescribeSubnets": func() error {
			_, err := c.ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{}, func(o *ec2.Options) { o.RetryMaxAttempts = 1 })
			return err
		},
		"ec2:DescribeAddresses": func() error {
			_, err := c.ec2Client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{}, func(o *ec2.Options) { o.RetryMaxAttempts = 1 })
			return err
		},
	}

	for perm, checkFunc := range checks {
		err := checkFunc()
		if err == nil {
			continue // permission exists
		}
		if isAccessDenied(err) {
			missingPermission = append(missingPermission, perm)
		}
	}

	return missingPermission, nil
}

// isAccessDenied returns true if the AWS error is an authorization failure.
// Uses smithy-go typed errors instead of string matching.
func isAccessDenied(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "UnauthorizedOperation",
			"AccessDenied",
			"AuthFailure",
			"InvalidClientTokenId":
			return true
		}
	}
	return false
}
