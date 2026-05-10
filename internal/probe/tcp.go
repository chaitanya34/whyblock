package probe

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// Prober defines the TCP probe interface.
// Using an interface allows tests to inject a mock prober
// without making real network connections.
type Prober interface {
	Probe(host string, port int, timeout time.Duration) Result
}

// Result holds the outcome of a single TCP probe attempt.
type Result struct {
	Outcome Outcome
	Latency time.Duration
}

// Outcome represents the result of a TCP connection attempt.
type Outcome string

const (
	// OutcomeSuccess means the TCP handshake completed — port is open
	OutcomeSuccess Outcome = "SUCCESS"

	// OutcomeRefused means a TCP RST was received — packet reached the
	// instance OS but nothing is listening or the OS rejected it
	OutcomeRefused Outcome = "REFUSED"

	// OutcomeTimeout means no response within the deadline —
	// traffic is being dropped somewhere before reaching the instance
	OutcomeTimeout Outcome = "TIMEOUT"

	// OutcomeSkipped means the probe was not attempted —
	// e.g. instance has no public IP or protocol is UDP
	OutcomeSkipped Outcome = "SKIPPED"
)

// TCPProber is the real implementation of Prober.
// It makes actual TCP connection attempts using the OS network stack.
type TCPProber struct{}

// NewTCPProber returns a new TCPProber.
func NewTCPProber() *TCPProber {
	return &TCPProber{}
}

// Probe attempts a TCP connection to host:port within the given timeout.
// It measures latency from dial start to first response received.
//
// The distinction between REFUSED and TIMEOUT is the most valuable signal:
//   - REFUSED: packet reached the OS — firewall layers passed, app problem
//   - TIMEOUT: packet never arrived — something in layers 1-5 is dropping it
func (p *TCPProber) Probe(host string, port int, timeout time.Duration) Result {
	address := fmt.Sprintf("%s:%d", host, port)

	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	latency := time.Since(start)

	if err == nil {
		// connection established — close immediately, we only needed
		// the handshake to confirm the port is open
		conn.Close()
		return Result{
			Outcome: OutcomeSuccess,
			Latency: latency,
		}
	}

	return Result{
		Outcome: classifyError(err, latency, timeout),
		Latency: latency,
	}
}

// classifyError determines whether a dial failure was a refused connection
// or a timeout. Uses the Go error chain to unwrap to the OS-level error.
func classifyError(err error, latency, timeout time.Duration) Outcome {
	// net.Error Timeout() == true means the deadline was exceeded
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return OutcomeTimeout
	}

	if isConnectionRefused(err) {
		return OutcomeRefused
	}

	// for unknown errors, if latency is close to the timeout
	// it almost certainly behaved like a timeout — treat it as one
	if latency >= timeout-100*time.Millisecond {
		return OutcomeTimeout
	}

	// default — safer to report timeout than a false positive
	return OutcomeTimeout
}

// isConnectionRefused checks if the error is a TCP RST (ECONNREFUSED).
// Unwraps the full error chain: error → *net.OpError → *os.SyscallError → syscall.Errno
func isConnectionRefused(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}

	var syscallErr *os.SyscallError
	if errors.As(opErr.Err, &syscallErr) {
		return errors.Is(syscallErr.Err, syscall.ECONNREFUSED)
	}

	// fallback: check the errno directly on the OpError inner error
	return errors.Is(opErr.Err, syscall.ECONNREFUSED)
}