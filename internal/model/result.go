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
	FixHint    string
	ConsoleURL string
}

// ProbeOutcome represents the result of a TCP probe attempt.
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

// VerdictStatus is the final reachability verdict.
type VerdictStatus string

const (
	VerdictReachable VerdictStatus = "REACHABLE"
	VerdictBlocked   VerdictStatus = "BLOCKED"
	VerdictPartial   VerdictStatus = "PARTIAL"
)

// Verdict is the correlated result from the analyzer.
// It is an internal struct — not exposed directly in CheckResult.
type Verdict struct {
	Status     VerdictStatus
	BlockedAt  string
	FixHint    string
	ConsoleURL string
}

// CheckResult is the complete output of a whyblock check command.
type CheckResult struct {
	Instance   InstanceInfo
	Port       int
	Proto      string
	Source     string
	Layers     []LayerResult
	Probe      ProbeResult
	Verdict    VerdictStatus // REACHABLE | BLOCKED | PARTIAL
	BlockedAt  string
	FixHint    string
	ConsoleURL string
}

// ExposedPort represents a single port found during an expose scan.
type ExposedPort struct {
	Port         int
	Proto        string
	SGRule       string
	NACLVerdict  LayerStatus
	ProbeOutcome ProbeOutcome
	Sensitive    bool
	Warning      string
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
	Direction string
	Protocol  string
	FromPort  int
	ToPort    int
	Source    string
}

// NACLRuleSummary is a human-readable NACL rule.
type NACLRuleSummary struct {
	NACLID     string
	RuleNumber int
	Direction  string
	Protocol   string
	PortRange  string
	CIDR       string
	Action     string
}

// RouteSummary is a human-readable route table entry.
type RouteSummary struct {
	Destination string
	Target      string
}
