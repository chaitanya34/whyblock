package analyzer

import (
	"testing"

	"github.com/chaitanya34/whyblock/internal/model"
	"github.com/chaitanya34/whyblock/internal/probe"
)

func TestCorrelate(t *testing.T) {
	allAllow := []model.LayerResult{
		{Layer: "Public IP", Status: model.StatusAllow},
		{Layer: "Internet Gateway", Status: model.StatusAllow},
		{Layer: "Route Table", Status: model.StatusAllow},
		{Layer: "NACL Inbound", Status: model.StatusAllow},
		{Layer: "Security Group", Status: model.StatusAllow},
	}

	tests := []struct {
		name           string
		layers         []model.LayerResult
		probeResult    probe.Result
		expectedStatus model.VerdictStatus
		expectedAt     string
	}{
		{
			name:           "all layers allow + probe success — reachable",
			layers:         allAllow,
			probeResult:    probe.Result{Outcome: probe.OutcomeSuccess},
			expectedStatus: model.VerdictReachable,
		},
		{
			name:           "all layers allow + probe refused — partial",
			layers:         allAllow,
			probeResult:    probe.Result{Outcome: probe.OutcomeRefused},
			expectedStatus: model.VerdictPartial,
			expectedAt:     "OS / Application",
		},
		{
			name:           "all layers allow + probe timeout — partial",
			layers:         allAllow,
			probeResult:    probe.Result{Outcome: probe.OutcomeTimeout},
			expectedStatus: model.VerdictPartial,
			expectedAt:     "OS Firewall",
		},
		{
			name:           "all layers allow + probe skipped — reachable",
			layers:         allAllow,
			probeResult:    probe.Result{Outcome: probe.OutcomeSkipped},
			expectedStatus: model.VerdictReachable,
		},
		{
			name: "blocked at layer 1 — public IP",
			layers: []model.LayerResult{
				{Layer: "Public IP", Status: model.StatusBlock,
					FixHint: "assign an EIP"},
			},
			probeResult:    probe.Result{Outcome: probe.OutcomeSkipped},
			expectedStatus: model.VerdictBlocked,
			expectedAt:     "Public IP",
		},
		{
			name: "blocked at layer 4 — NACL",
			layers: []model.LayerResult{
				{Layer: "Public IP", Status: model.StatusAllow},
				{Layer: "Internet Gateway", Status: model.StatusAllow},
				{Layer: "Route Table", Status: model.StatusAllow},
				{Layer: "NACL Inbound", Status: model.StatusBlock,
					FixHint: "add ALLOW rule"},
			},
			probeResult:    probe.Result{Outcome: probe.OutcomeSkipped},
			expectedStatus: model.VerdictBlocked,
			expectedAt:     "NACL Inbound",
		},
		{
			name: "blocked at layer 5 — security group",
			layers: []model.LayerResult{
				{Layer: "Public IP", Status: model.StatusAllow},
				{Layer: "Internet Gateway", Status: model.StatusAllow},
				{Layer: "Route Table", Status: model.StatusAllow},
				{Layer: "NACL Inbound", Status: model.StatusAllow},
				{Layer: "Security Group", Status: model.StatusBlock,
					FixHint: "add inbound rule"},
			},
			probeResult:    probe.Result{Outcome: probe.OutcomeSkipped},
			expectedStatus: model.VerdictBlocked,
			expectedAt:     "Security Group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := Correlate(tt.layers, tt.probeResult)

			if verdict.Status != tt.expectedStatus {
				t.Errorf("Status = %q, want %q", verdict.Status, tt.expectedStatus)
			}
			if tt.expectedAt != "" && verdict.BlockedAt != tt.expectedAt {
				t.Errorf("BlockedAt = %q, want %q", verdict.BlockedAt, tt.expectedAt)
			}
		})
	}
}
