package model

import "time"

// LayerStatus represents the verdict for a single network layer.
type LayerStatus string

const (
	StatusAllow   LayerStatus = "ALLOW"
	StatusBlock   LayerStatus = "BLOCK"
	StatusSkipped LayerStatus = "SKIPPED"
)

// LayerResult is the verdict for one network layer check.
type LayerResult struct {
	Layer      string
	Detail     string
	Status     LayerStatus
	FixHint    string // populated only when Status == BLOCK
	ConsoleURL string // direct AWS console deep-link when Status == BLOCK
}

// ProbeOutcome represents the result of the TCP probe.
type ProbeOutcome string

const (
	ProbeSuccess ProbeOutcome = "SUCCESS"
	ProbeRefused ProbeOutcome = "REFUSED"
	ProbeTimeout ProbeOutcome = "TIMEOUT"
	ProbeSkipped ProbeOutcome = "SKIPPED"
)

// ProbeResult holds the TCP probe outcome.
type ProbeResult struct {
	Outcome ProbeOutcome
	Latency time.Duration
}

// Verdict is the final cross-referenced result.
type Verdict string

const (
	VerdictReachable Verdict = "REACHABLE"
	VerdictBlocked   Verdict = "BLOCKED"
	VerdictPartial   Verdict = "PARTIAL" // AWS layers pass but TCP probe differs
)

// CheckResult is the complete output of a whyblock check command.
type CheckResult struct {
	Instance   InstanceInfo
	Port       int
	Proto      string
	Source     string
	Layers     []LayerResult
	Probe      ProbeResult
	Verdict    Verdict
	BlockedAt  string // layer name where block occurred
	FixHint    string
	ConsoleURL string
}

// ExposedPort represents a single port found during an expose scan.
type ExposedPort struct {
	Port         int
	Proto        string
	SGRule       string // which SG rule opened this port
	NACLVerdict  LayerStatus
	ProbeOutcome ProbeOutcome
	Sensitive    bool   // true for known sensitive ports (SSH, DB ports etc.)
	Warning      string // populated when Sensitive == true
}

// ExposeResult is the complete output of a whyblock expose command.
type ExposeResult struct {
	Instance InstanceInfo
	Source   string
	Ports    []ExposedPort
}

// RulesResult is the complete output of a whyblock rules command.
type RulesResult struct {
	Instance    InstanceInfo
	SGRules     []SGRuleSummary
	NACLRules   []NACLRuleSummary
	Routes      []RouteSummary
	IGWAttached bool
	IGWID       string
}

// SGRuleSummary is a human-readable Security Group rule.
type SGRuleSummary struct {
	SGID      string
	SGName    string
	Direction string // inbound | outbound
	Protocol  string
	FromPort  int
	ToPort    int
	Source    string
}

// NACLRuleSummary is a human-readable NACL rule.
type NACLRuleSummary struct {
	NACLID     string
	RuleNumber int
	Direction  string // inbound | outbound
	Protocol   string
	PortRange  string
	CIDR       string
	Action     string // ALLOW | DENY
}

// RouteSummary is a human-readable route table entry.
type RouteSummary struct {
	Destination string
	Target      string
}
