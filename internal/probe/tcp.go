package probe

import "time"

// Prober defines the TCP probe interface.
type Prober interface {
	Probe(host string, port int, timeout time.Duration) ProbeResult
}

// ProbeResult holds the outcome of a TCP probe attempt.
type ProbeResult struct {
	Outcome string // SUCCESS | REFUSED | TIMEOUT | SKIPPED
	Latency time.Duration
}

// TODO: implement TCPProber using net.DialTimeout
