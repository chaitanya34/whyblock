package analyzer

import (
	"context"
	"fmt"

	"github.com/chaitanya34/whyblock/internal/aws"
	awsinternal "github.com/chaitanya34/whyblock/internal/aws"
	"github.com/chaitanya34/whyblock/internal/model"
	"github.com/chaitanya34/whyblock/internal/probe"
)

// Analyzer defines the core analysis operations.
// type Analyzer interface {
// 	Check(ctx context.Context, opts model.CheckOptions) (model.CheckResult, error)
// 	Expose(ctx context.Context, opts model.ExposeOptions) (model.ExposeResult, error)
// 	Rules(ctx context.Context, opts model.RulesOptions) (model.RulesResult, error)
// }

// TODO: implement WhyblockAnalyzer struct that satisfies Analyzer

// Analyzer orchestrates all layer checks and produces a CheckResult.
type Analyzer struct {
	client aws.AWSClient
	prober probe.Prober
}

// NewAnalyzer returns a new Analyzer with the given AWS client and prober.
func NewAnalyzer(client aws.AWSClient, prober probe.Prober) *Analyzer {
	return &Analyzer{
		client: client,
		prober: prober,
	}
}

// Check runs the full layer-by-layer connectivity analysis for a given
// instance, port, protocol, and source IP.
// It stops at the first blocking layer for AWS checks but always
// runs the TCP probe for ground truth.
func (a *Analyzer) Check(ctx context.Context, opts model.CheckOptions) (model.CheckResult, error) {
	// step 1 — validate IAM permissions before doing anything
	missing, err := a.client.ValidatePermissions(ctx)
	if err != nil {
		return model.CheckResult{}, fmt.Errorf("permission check failed: %w", err)
	}
	if len(missing) > 0 {
		return model.CheckResult{}, &MissingPermissionsError{Permissions: missing}
	}

	// step 2 — resolve instance metadata
	instance, err := a.client.GetInstance(ctx, opts.InstanceID)
	if err != nil {
		return model.CheckResult{}, fmt.Errorf("failed to resolve instance: %w", err)
	}

	// step 3 — warn if instance is not running
	// we still run AWS layer checks but skip TCP probe
	if instance.State != "running" {
		return a.buildStoppedResult(instance, opts), nil
	}

	// step 4 — check for EIP separately
	// EIP takes precedence over auto-assigned public IP
	eip, err := a.client.GetEIP(ctx, opts.InstanceID)
	if err != nil {
		// non-fatal — continue without EIP info
		eip = ""
	}

	// step 5 — run layer checks top-down
	// stop at first block — no point checking lower layers
	layers := make([]model.LayerResult, 0, 5)

	// Layer 1 — public IP
	l1 := checkPublicIP(instance, eip)
	layers = append(layers, l1)
	if l1.Status == model.StatusBlock {
		return a.buildResult(instance, opts, layers, probe.Result{
			Outcome: probe.OutcomeSkipped,
		}), nil
	}

	// Layer 2 — IGW
	l2 := checkIGW(ctx, a.client, instance.VPCID)
	layers = append(layers, l2)
	if l2.Status == model.StatusBlock {
		return a.buildResult(instance, opts, layers, probe.Result{
			Outcome: probe.OutcomeSkipped,
		}), nil
	}

	// Layer 3 — route table
	l3 := checkRouteTable(ctx, a.client, instance.SubnetID, instance.Region)
	layers = append(layers, l3)
	if l3.Status == model.StatusBlock {
		return a.buildResult(instance, opts, layers, probe.Result{
			Outcome: probe.OutcomeSkipped,
		}), nil
	}

	// Layer 4 — NACL
	l4 := checkNACL(
		ctx, a.client,
		instance.SubnetID,
		opts.Port, opts.Proto, opts.From,
		instance.Region,
	)
	layers = append(layers, l4)
	if l4.Status == model.StatusBlock {
		return a.buildResult(instance, opts, layers, probe.Result{
			Outcome: probe.OutcomeSkipped,
		}), nil
	}

	// Layer 5 — security group
	l5 := checkSG(
		ctx, a.client,
		instance.SecurityGroups,
		opts.Port, opts.Proto, opts.From,
		instance.Region,
	)
	layers = append(layers, l5)
	if l5.Status == model.StatusBlock {
		return a.buildResult(instance, opts, layers, probe.Result{
			Outcome: probe.OutcomeSkipped,
		}), nil
	}

	// step 6 — all AWS layers passed — run TCP probe
	publicIP := eip
	if publicIP == "" {
		publicIP = instance.PublicIP
	}

	probeResult := probe.Result{Outcome: probe.OutcomeSkipped}

	// skip probe for UDP — no reliable handshake to probe
	if opts.Proto == "tcp" {
		probeResult = a.prober.Probe(
			publicIP,
			opts.Port,
			opts.TimeoutDuration(),
		)
	}

	return a.buildResult(instance, opts, layers, probeResult), nil
}

// buildResult assembles the final CheckResult from all collected data.
func (a *Analyzer) buildResult(
	instance aws.InstanceData,
	opts model.CheckOptions,
	layers []model.LayerResult,
	probeResult probe.Result,
) model.CheckResult {
	verdict := Correlate(layers, probeResult)

	return model.CheckResult{
		Instance: model.InstanceInfo{
			InstanceID:     instance.InstanceID,
			PublicIP:       instance.PublicIP,
			PrivateIP:      instance.PrivateIP,
			VPCID:          instance.VPCID,
			SubnetID:       instance.SubnetID,
			SecurityGroups: instance.SecurityGroups,
			Region:         instance.Region,
			State:          instance.State,
		},
		Port:       opts.Port,
		Proto:      opts.Proto,
		Source:     opts.From,
		Layers:     layers,
		Probe:      probeResultToModel(probeResult),
		Verdict:    verdict.Status,
		BlockedAt:  verdict.BlockedAt,
		FixHint:    verdict.FixHint,
		ConsoleURL: verdict.ConsoleURL,
	}
}

// buildStoppedResult returns a result for a stopped instance.
// AWS layer checks are still shown but TCP probe is skipped.
func (a *Analyzer) buildStoppedResult(
	instance aws.InstanceData,
	opts model.CheckOptions,
) model.CheckResult {
	return model.CheckResult{
		Instance: model.InstanceInfo{
			InstanceID: instance.InstanceID,
			State:      instance.State,
		},
		Port:      opts.Port,
		Proto:     opts.Proto,
		Source:    opts.From,
		Verdict:   model.VerdictBlocked,
		BlockedAt: "Instance",
		FixHint:   fmt.Sprintf("instance is %s — start it first", instance.State),
		Probe:     model.ProbeResult{Outcome: model.ProbeSkipped},
	}
}

// MissingPermissionsError is returned when required IAM permissions are absent.
// It is a typed error so the cmd layer can format it clearly.
type MissingPermissionsError struct {
	Permissions []string
}

func (e *MissingPermissionsError) Error() string {
	return fmt.Sprintf("missing IAM permissions: %s", e.Permissions)
}

func probeResultToModel(r probe.Result) model.ProbeResult {
	return model.ProbeResult{
		Outcome: model.ProbeOutcome(r.Outcome),
		Latency: r.Latency,
	}
}

// Expose discovers all ports reachable from the given source on the instance.
func (a *Analyzer) Expose(ctx context.Context, opts model.ExposeOptions) (model.ExposeResult, error) {
	missing, err := a.client.ValidatePermissions(ctx)
	if err != nil {
		return model.ExposeResult{}, fmt.Errorf("permission check failed: %w", err)
	}
	if len(missing) > 0 {
		return model.ExposeResult{}, &MissingPermissionsError{Permissions: missing}
	}

	instance, err := a.client.GetInstance(ctx, opts.InstanceID)
	if err != nil {
		return model.ExposeResult{}, fmt.Errorf("failed to resolve instance: %w", err)
	}

	// fetch all SG rules to find every open port
	sgs, err := a.client.GetSecurityGroups(ctx, instance.SecurityGroups)
	if err != nil {
		return model.ExposeResult{}, fmt.Errorf("failed to get security groups: %w", err)
	}

	// collect all unique inbound ports allowed by SGs
	ports := collectOpenPorts(sgs)

	result := model.ExposeResult{
		Instance: model.InstanceInfo{
			InstanceID: instance.InstanceID,
			PublicIP:   instance.PublicIP,
			Region:     instance.Region,
		},
		Source: opts.From,
		Ports:  make([]model.ExposedPort, 0, len(ports)),
	}

	publicIP := instance.PublicIP

	for _, p := range ports {
		// evaluate NACL for this port
		naclResult := checkNACL(
			ctx, a.client,
			instance.SubnetID,
			p.port, p.proto, opts.From,
			instance.Region,
		)

		// TCP probe only if NACL allows and instance is running
		probeOutcome := model.ProbeSkipped
		if naclResult.Status == model.StatusAllow &&
			instance.State == "running" &&
			p.proto == "tcp" &&
			publicIP != "" {
			pr := a.prober.Probe(publicIP, p.port, 3*1000000000) // 3s timeout
			probeOutcome = model.ProbeOutcome(pr.Outcome)
		}

		exposed := model.ExposedPort{
			Port:         p.port,
			Proto:        p.proto,
			SGRule:       p.sgID + ": ALLOW " + p.proto,
			NACLVerdict:  naclResult.Status,
			ProbeOutcome: probeOutcome,
			Sensitive:    isSensitivePort(p.port),
		}

		if exposed.Sensitive {
			exposed.Warning = sensitivePortWarning(p.port)
		}

		result.Ports = append(result.Ports, exposed)
	}

	return result, nil
}

// Rules fetches all effective network rules for an instance.
func (a *Analyzer) Rules(ctx context.Context, opts model.RulesOptions) (model.RulesResult, error) {
	missing, err := a.client.ValidatePermissions(ctx)
	if err != nil {
		return model.RulesResult{}, fmt.Errorf("permission check failed: %w", err)
	}
	if len(missing) > 0 {
		return model.RulesResult{}, &MissingPermissionsError{Permissions: missing}
	}

	instance, err := a.client.GetInstance(ctx, opts.InstanceID)
	if err != nil {
		return model.RulesResult{}, fmt.Errorf("failed to resolve instance: %w", err)
	}

	// fetch all components in parallel would be ideal but
	// sequential is simpler and correct for v1
	sgs, err := a.client.GetSecurityGroups(ctx, instance.SecurityGroups)
	if err != nil {
		return model.RulesResult{}, err
	}

	nacl, err := a.client.GetNACL(ctx, instance.SubnetID)
	if err != nil {
		return model.RulesResult{}, err
	}

	rt, err := a.client.GetRouteTable(ctx, instance.SubnetID)
	if err != nil {
		return model.RulesResult{}, err
	}

	igw, err := a.client.GetIGW(ctx, instance.VPCID)
	if err != nil {
		return model.RulesResult{}, err
	}

	return model.RulesResult{
		Instance:    mapInstanceInfo(instance),
		SGRules:     mapSGRuleSummaries(sgs),
		NACLRules:   mapNACLRuleSummaries(nacl),
		Routes:      mapRouteSummaries(rt),
		IGWAttached: igw.Attached,
		IGWID:       igw.ID,
	}, nil
}

// openPort is an internal struct for collecting SG-allowed ports.
type openPort struct {
	port  int
	proto string
	sgID  string
}

// collectOpenPorts extracts all unique inbound ports from SG rules.
func collectOpenPorts(sgs []awsinternal.SecurityGroup) []openPort {
	seen := make(map[string]bool)
	result := make([]openPort, 0)

	for _, sg := range sgs {
		for _, rule := range sg.Rules {
			if rule.Direction != "inbound" {
				continue
			}
			// for port ranges, check each individual port
			// cap at 1024 ports per range to avoid scanning entire range
			from := rule.FromPort
			to := rule.ToPort
			if from == 0 && to == 0 {
				// all-traffic rule — we can't enumerate all 65535 ports
				// add a representative entry
				key := fmt.Sprintf("%s:0", rule.Protocol)
				if !seen[key] {
					seen[key] = true
					result = append(result, openPort{
						port: 0, proto: rule.Protocol, sgID: sg.ID,
					})
				}
				continue
			}
			for p := from; p <= to && p <= from+1024; p++ {
				key := fmt.Sprintf("%s:%d", rule.Protocol, p)
				if !seen[key] {
					seen[key] = true
					result = append(result, openPort{
						port: p, proto: rule.Protocol, sgID: sg.ID,
					})
				}
			}
		}
	}
	return result
}

// sensitivePortWarning returns a warning message for sensitive ports.
var sensitivePorts = map[int]string{
	22:    "SSH exposed to 0.0.0.0/0",
	3389:  "RDP exposed to 0.0.0.0/0",
	3306:  "MySQL exposed to 0.0.0.0/0",
	5432:  "PostgreSQL exposed to 0.0.0.0/0",
	27017: "MongoDB exposed to 0.0.0.0/0",
	6379:  "Redis exposed to 0.0.0.0/0",
	9200:  "Elasticsearch exposed to 0.0.0.0/0",
	2375:  "Docker daemon exposed to 0.0.0.0/0",
}

func isSensitivePort(port int) bool {
	_, ok := sensitivePorts[port]
	return ok
}

func sensitivePortWarning(port int) string {
	if w, ok := sensitivePorts[port]; ok {
		return w
	}
	return ""
}

// mapInstanceInfo converts aws.InstanceData to model.InstanceInfo.
func mapInstanceInfo(i awsinternal.InstanceData) model.InstanceInfo {
	return model.InstanceInfo{
		InstanceID:     i.InstanceID,
		PublicIP:       i.PublicIP,
		PrivateIP:      i.PrivateIP,
		VPCID:          i.VPCID,
		SubnetID:       i.SubnetID,
		SecurityGroups: i.SecurityGroups,
		Region:         i.Region,
		State:          i.State,
	}
}

// mapSGRuleSummaries converts SG rules to model summaries for display.
func mapSGRuleSummaries(sgs []awsinternal.SecurityGroup) []model.SGRuleSummary {
	result := make([]model.SGRuleSummary, 0)
	for _, sg := range sgs {
		for _, rule := range sg.Rules {
			result = append(result, model.SGRuleSummary{
				SGID:      sg.ID,
				SGName:    sg.Name,
				Direction: rule.Direction,
				Protocol:  rule.Protocol,
				FromPort:  rule.FromPort,
				ToPort:    rule.ToPort,
				Source:    rule.CIDR,
			})
		}
	}
	return result
}

// mapNACLRuleSummaries converts NACL rules to model summaries for display.
func mapNACLRuleSummaries(nacl awsinternal.NACL) []model.NACLRuleSummary {
	result := make([]model.NACLRuleSummary, 0, len(nacl.Rules))
	for _, rule := range nacl.Rules {
		portRange := "ALL"
		if rule.FromPort != 0 || rule.ToPort != 0 {
			if rule.FromPort == rule.ToPort {
				portRange = fmt.Sprintf("%d", rule.FromPort)
			} else {
				portRange = fmt.Sprintf("%d-%d", rule.FromPort, rule.ToPort)
			}
		}
		result = append(result, model.NACLRuleSummary{
			NACLID:     nacl.ID,
			RuleNumber: rule.RuleNumber,
			Direction:  rule.Direction,
			Protocol:   rule.Protocol,
			PortRange:  portRange,
			CIDR:       rule.CIDR,
			Action:     rule.Action,
		})
	}
	return result
}

// mapRouteSummaries converts route table entries to model summaries.
func mapRouteSummaries(rt awsinternal.RouteTable) []model.RouteSummary {
	result := make([]model.RouteSummary, 0, len(rt.Routes))
	for _, r := range rt.Routes {
		result = append(result, model.RouteSummary{
			Destination: r.Destination,
			Target:      r.Target,
		})
	}
	return result
}
