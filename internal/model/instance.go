package model

// InstanceInfo holds resolved metadata about an EC2 instance.
type InstanceInfo struct {
	InstanceID     string
	PublicIP       string // empty if not assigned
	PrivateIP      string
	VPCID          string
	SubnetID       string
	SecurityGroups []string // list of sg-xxx IDs
	Region         string
	State          string // running | stopped | terminated
}
