package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/chaitanya34/whyblock/internal/model"
	"github.com/fatih/color"
)

// symbols used in the verdict column
const (
	symbolAllow   = "✓"
	symbolBlock   = "✗"
	symbolSkipped = "⚠"
	symbolWarning = "⚠"
)

// column widths — fixed for consistent alignment
const (
	colLayer   = 20
	colDetail  = 44
	colVerdict = 12
)

var (
	green  = color.New(color.FgGreen, color.Bold)
	red    = color.New(color.FgRed, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	bold   = color.New(color.Bold)
	cyan   = color.New(color.FgCyan)
	white  = color.New(color.FgWhite)
	grey   = color.New(color.FgHiBlack)
)

// RenderCheck writes the full layer-by-layer check result to w.
func RenderCheck(w io.Writer, result model.CheckResult) {
	renderCheckHeader(w, result)
	renderDivider(w)
	renderColumnHeaders(w)
	renderDivider(w)
	renderLayers(w, result.Layers)
	renderProbe(w, result.Probe)
	renderDivider(w)
	renderVerdict(w, result)
}

// RenderExpose writes the exposure report to w.
func RenderExpose(w io.Writer, result model.ExposeResult) {
	renderExposeHeader(w, result)
	renderDivider(w)
	renderExposeColumnHeaders(w)
	renderDivider(w)
	renderExposedPorts(w, result.Ports)
	renderDivider(w)
	renderExposeSummary(w, result.Ports)
}

// RenderRules writes all effective rules for an instance to w.
func RenderRules(w io.Writer, result model.RulesResult) {
	renderRulesHeader(w, result)
	renderSGRules(w, result.SGRules)
	renderNACLRules(w, result.NACLRules)
	renderRoutes(w, result.Routes, result.IGWAttached, result.IGWID)
}

// ── Check rendering ──────────────────────────────────────────────────────────

func renderCheckHeader(w io.Writer, result model.CheckResult) {
	fmt.Fprintln(w)
	cyan.Fprintf(w, "  Checking %s", result.Instance.InstanceID)
	white.Fprintf(w, "  ·  port %d/%s  ·  from %s\n",
		result.Port, result.Proto, result.Source)
	fmt.Fprintln(w)
}

func renderColumnHeaders(w io.Writer) {
	bold.Fprintf(w, "  %-*s  %-*s  %s\n",
		colLayer, "LAYER",
		colDetail, "DETAIL",
		"VERDICT",
	)
}

func renderDivider(w io.Writer) {
	grey.Fprintf(w, "  %s\n", strings.Repeat("─", colLayer+colDetail+colVerdict+4))
}

func renderLayers(w io.Writer, layers []model.LayerResult) {
	for _, layer := range layers {
		renderLayerRow(w, layer)
	}
}

func renderLayerRow(w io.Writer, layer model.LayerResult) {
	symbol, colorFn := verdictStyle(layer.Status)

	// truncate detail if too long for column
	detail := truncate(layer.Detail, colDetail)

	fmt.Fprintf(w, "  %-*s  %-*s  ",
		colLayer, layer.Layer,
		colDetail, detail,
	)
	colorFn.Fprintf(w, "%s %s\n", symbol, statusLabel(layer.Status))

	// if detail has multiple lines (e.g. SG allowed ports hint)
	// print the continuation lines indented under the detail column
	lines := strings.Split(layer.Detail, "\n")
	for _, line := range lines[1:] {
		fmt.Fprintf(w, "  %-*s  %s\n",
			colLayer, "",
			grey.Sprint(truncate(strings.TrimSpace(line), colDetail)),
		)
	}
}

func renderProbe(w io.Writer, probe model.ProbeResult) {
	if probe.Outcome == model.ProbeSkipped {
		fmt.Fprintf(w, "  %-*s  %-*s  ",
			colLayer, "TCP Probe",
			colDetail, "skipped",
		)
		yellow.Fprintf(w, "%s skipped\n", symbolSkipped)
		return
	}

	var detail string
	var symbol string
	var colorFn *color.Color

	switch probe.Outcome {
	case model.ProbeSuccess:
		detail = fmt.Sprintf("SYN-ACK received (%s)", probe.Latency.Round(1*1000000))
		symbol = symbolAllow
		colorFn = green
	case model.ProbeRefused:
		detail = "connection refused — app not listening"
		symbol = symbolBlock
		colorFn = red
	case model.ProbeTimeout:
		detail = fmt.Sprintf("timeout after %s", probe.Latency.Round(1*1000000))
		symbol = symbolBlock
		colorFn = red
	default:
		detail = string(probe.Outcome)
		symbol = symbolSkipped
		colorFn = yellow
	}

	fmt.Fprintf(w, "  %-*s  %-*s  ",
		colLayer, "TCP Probe",
		colDetail, detail,
	)
	colorFn.Fprintf(w, "%s %s\n", symbol, probeLabel(probe.Outcome))
}

func renderVerdict(w io.Writer, result model.CheckResult) {
	fmt.Fprintln(w)

	switch result.Verdict {
	case model.VerdictReachable:
		green.Fprintf(w, "  RESULT:  %s  Port %d is reachable on %s\n",
			symbolAllow, result.Port, result.Instance.InstanceID)

	case model.VerdictBlocked:
		red.Fprintf(w, "  RESULT:  %s  Blocked at %s\n",
			symbolBlock, result.BlockedAt)
		if result.FixHint != "" {
			fmt.Fprintf(w, "  FIX:     %s\n", result.FixHint)
		}
		if result.ConsoleURL != "" {
			cyan.Fprintf(w, "  LINK:    %s\n", result.ConsoleURL)
		}

	case model.VerdictPartial:
		yellow.Fprintf(w, "  RESULT:  %s  Blocked at %s\n",
			symbolWarning, result.BlockedAt)
		if result.FixHint != "" {
			fmt.Fprintf(w, "  FIX:     %s\n", result.FixHint)
		}
	}

	fmt.Fprintln(w)
}

// ── Expose rendering ─────────────────────────────────────────────────────────

func renderExposeHeader(w io.Writer, result model.ExposeResult) {
	fmt.Fprintln(w)
	cyan.Fprintf(w, "  Exposure report for %s", result.Instance.InstanceID)
	white.Fprintf(w, "  ·  from %s\n", result.Source)
	fmt.Fprintln(w)
}

func renderExposeColumnHeaders(w io.Writer) {
	bold.Fprintf(w, "  %-6s  %-5s  %-24s  %-8s  %-10s  %s\n",
		"PORT", "PROTO", "SG RULE", "NACL", "TCP PROBE", "WARNING",
	)
}

func renderExposedPorts(w io.Writer, ports []model.ExposedPort) {
	for _, p := range ports {
		probeStr, probeColor := probeStyle(p.ProbeOutcome)
		naclStr, naclColor := naclStyle(p.NACLVerdict)
		warning := ""
		if p.Sensitive {
			warning = yellow.Sprint("⚠  " + p.Warning)
		}

		fmt.Fprintf(w, "  %-6d  %-5s  %-24s  ",
			p.Port, p.Proto,
			truncate(p.SGRule, 24),
		)
		naclColor.Fprintf(w, "%-8s  ", naclStr)
		probeColor.Fprintf(w, "%-10s  ", probeStr)
		fmt.Fprintln(w, warning)
	}
}

func renderExposeSummary(w io.Writer, ports []model.ExposedPort) {
	total := len(ports)
	open := 0
	naclBlocked := 0
	notListening := 0
	sensitive := 0

	for _, p := range ports {
		switch p.ProbeOutcome {
		case model.ProbeSuccess:
			open++
		case model.ProbeRefused:
			notListening++
		case model.ProbeTimeout:
			if p.NACLVerdict == model.StatusBlock {
				naclBlocked++
			}
		}
		if p.Sensitive {
			sensitive++
		}
	}

	fmt.Fprintln(w)
	bold.Fprintf(w, "  SUMMARY\n")
	fmt.Fprintf(w, "  %d ports found in Security Group rules\n", total)

	if open > 0 {
		green.Fprintf(w, "  %s  %d port(s) fully reachable\n", symbolAllow, open)
	}
	if naclBlocked > 0 {
		yellow.Fprintf(w, "  %s  %d port(s) open in SG but blocked by NACL\n",
			symbolWarning, naclBlocked)
	}
	if notListening > 0 {
		yellow.Fprintf(w, "  %s  %d port(s) open in SG but app not listening\n",
			symbolWarning, notListening)
	}
	if sensitive > 0 {
		red.Fprintf(w, "  %s  %d sensitive port(s) exposed to %s — review recommended\n",
			symbolBlock, sensitive, "0.0.0.0/0")
	}

	fmt.Fprintln(w)
}

// ── Rules rendering ──────────────────────────────────────────────────────────

func renderRulesHeader(w io.Writer, result model.RulesResult) {
	fmt.Fprintln(w)
	cyan.Fprintf(w, "  %s", result.Instance.InstanceID)
	white.Fprintf(w, "  ·  %s  ·  %s\n",
		result.Instance.PublicIP, result.Instance.Region)
	grey.Fprintf(w, "  VPC: %s  ·  Subnet: %s\n",
		result.Instance.VPCID, result.Instance.SubnetID)
	fmt.Fprintln(w)
}

func renderSGRules(w io.Writer, rules []model.SGRuleSummary) {
	bold.Fprintf(w, "  SECURITY GROUPS\n")
	renderDividerShort(w)

	if len(rules) == 0 {
		grey.Fprintf(w, "  no rules found\n")
		fmt.Fprintln(w)
		return
	}

	currentSG := ""
	for _, r := range rules {
		if r.SGID != currentSG {
			currentSG = r.SGID
			fmt.Fprintf(w, "\n  %s (%s)\n", bold.Sprint(r.SGID), r.SGName)
		}

		directionColor := green
		if r.Direction == "outbound" {
			directionColor = grey
		}

		portStr := fmt.Sprintf("%d", r.FromPort)
		if r.FromPort != r.ToPort {
			portStr = fmt.Sprintf("%d-%d", r.FromPort, r.ToPort)
		}
		if r.FromPort == 0 && r.ToPort == 0 {
			portStr = "ALL"
		}

		fmt.Fprintf(w, "    ")
		directionColor.Fprintf(w, "%-9s", strings.ToUpper(r.Direction))
		fmt.Fprintf(w, "  %-5s  %-10s  %s\n",
			r.Protocol, portStr, r.Source)
	}
	fmt.Fprintln(w)
}

func renderNACLRules(w io.Writer, rules []model.NACLRuleSummary) {
	bold.Fprintf(w, "  NETWORK ACL\n")
	renderDividerShort(w)

	if len(rules) == 0 {
		grey.Fprintf(w, "  no rules found\n")
		fmt.Fprintln(w)
		return
	}

	currentNACL := ""
	for _, r := range rules {
		if r.NACLID != currentNACL {
			currentNACL = r.NACLID
			fmt.Fprintf(w, "\n  %s\n", bold.Sprint(r.NACLID))
		}

		actionColor := green
		if r.Action == "DENY" {
			actionColor = red
		}

		fmt.Fprintf(w, "    %-9s  Rule %-6d  %-5s  %-16s  %-20s  ",
			strings.ToUpper(r.Direction),
			r.RuleNumber,
			r.Protocol,
			r.PortRange,
			r.CIDR,
		)
		actionColor.Fprintf(w, "%s\n", r.Action)
	}
	fmt.Fprintln(w)
}

func renderRoutes(w io.Writer, routes []model.RouteSummary, igwAttached bool, igwID string) {
	bold.Fprintf(w, "  ROUTE TABLE\n")
	renderDividerShort(w)

	for _, r := range routes {
		fmt.Fprintf(w, "    %-20s  →  %s\n", r.Destination, r.Target)
	}
	fmt.Fprintln(w)

	bold.Fprintf(w, "  INTERNET GATEWAY\n")
	renderDividerShort(w)

	if igwAttached {
		green.Fprintf(w, "    %s  %s  attached\n", symbolAllow, igwID)
	} else {
		red.Fprintf(w, "    %s  no Internet Gateway attached\n", symbolBlock)
	}
	fmt.Fprintln(w)
}

func renderDividerShort(w io.Writer) {
	grey.Fprintf(w, "  %s\n", strings.Repeat("─", 60))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func verdictStyle(status model.LayerStatus) (string, *color.Color) {
	switch status {
	case model.StatusAllow:
		return symbolAllow, green
	case model.StatusBlock:
		return symbolBlock, red
	default:
		return symbolSkipped, yellow
	}
}

func statusLabel(status model.LayerStatus) string {
	switch status {
	case model.StatusAllow:
		return "allowed"
	case model.StatusBlock:
		return "BLOCKED"
	default:
		return "skipped"
	}
}

func probeLabel(outcome model.ProbeOutcome) string {
	switch outcome {
	case model.ProbeSuccess:
		return "open"
	case model.ProbeRefused:
		return "refused"
	case model.ProbeTimeout:
		return "timeout"
	default:
		return "skipped"
	}
}

func probeStyle(outcome model.ProbeOutcome) (string, *color.Color) {
	switch outcome {
	case model.ProbeSuccess:
		return symbolAllow + " open", green
	case model.ProbeRefused:
		return symbolBlock + " refused", yellow
	case model.ProbeTimeout:
		return symbolBlock + " timeout", red
	default:
		return symbolSkipped + " skipped", grey
	}
}

func naclStyle(status model.LayerStatus) (string, *color.Color) {
	switch status {
	case model.StatusAllow:
		return "ALLOW", green
	case model.StatusBlock:
		return "DENY", red
	default:
		return "unknown", grey
	}
}

// truncate shortens a string to maxLen, adding "…" if truncated.
func truncate(s string, maxLen int) string {
	// only use the first line for column display
	// multiline details are handled by the continuation renderer
	line := strings.SplitN(s, "\n", 2)[0]
	if len(line) <= maxLen {
		return line
	}
	return line[:maxLen-1] + "…"
}
