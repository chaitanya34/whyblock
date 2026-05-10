package analyzer

import (
	"github.com/chaitanya34/whyblock/internal/model"
	"github.com/chaitanya34/whyblock/internal/probe"
)

// Correlate takes the AWS layer results and the TCP probe result
// and produces the final unified verdict.
//
// The four combinations that matter:
//
//	AWS ALLOW + TCP Success  → fully reachable
//	AWS ALLOW + TCP Refused  → AWS layers passed, app not listening
//	AWS ALLOW + TCP Timeout  → AWS layers passed, OS firewall likely blocking
//	AWS BLOCK at layer N     → blocked at that layer (probe confirms)
func Correlate(layers []model.LayerResult, probeResult probe.Result) model.Verdict {
	blockedLayer := findBlockedLayer(layers)

	if blockedLayer != nil {
		return model.Verdict{
			Status:     model.VerdictBlocked,
			BlockedAt:  blockedLayer.Layer,
			FixHint:    blockedLayer.FixHint,
			ConsoleURL: blockedLayer.ConsoleURL,
		}
	}

	switch probeResult.Outcome {
	case probe.OutcomeSuccess:
		return model.Verdict{Status: model.VerdictReachable}

	case probe.OutcomeRefused:
		return model.Verdict{
			Status:    model.VerdictPartial,
			BlockedAt: "OS / Application",
			FixHint: "AWS layers are open but the connection was refused. " +
				"Check that your application is running and bound to 0.0.0.0 not 127.0.0.1",
		}

	case probe.OutcomeTimeout:
		return model.Verdict{
			Status:    model.VerdictPartial,
			BlockedAt: "OS Firewall",
			FixHint: "AWS layers are open but the TCP probe timed out. " +
				"Check OS-level firewall: sudo iptables -L or sudo ufw status",
		}

	case probe.OutcomeSkipped:
		return model.Verdict{Status: model.VerdictReachable}
	}

	return model.Verdict{Status: model.VerdictReachable}
}

// findBlockedLayer returns the first LayerResult with StatusBlock.
// Returns nil if all layers passed.
func findBlockedLayer(layers []model.LayerResult) *model.LayerResult {
	for i := range layers {
		if layers[i].Status == model.StatusBlock {
			return &layers[i]
		}
	}
	return nil
}
