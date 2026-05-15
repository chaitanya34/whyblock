package probe

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// startTestServer starts a real TCP server on a random port.
// Returns the port and a cancel function to stop it.
func startTestServer(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}

	// accept connections in background — we just need the port to be open
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed
			}
			conn.Close()
		}
	}()

	// register cleanup — stop the server when the test ends
	t.Cleanup(func() { listener.Close() })

	return listener.Addr().(*net.TCPAddr).Port
}

func TestTCPProberProbe(t *testing.T) {
	prober := NewTCPProber()

	t.Run("success — real open port", func(t *testing.T) {
		port := startTestServer(t)

		result := prober.Probe("127.0.0.1", port, 3*time.Second)

		if result.Outcome != OutcomeSuccess {
			t.Errorf("Outcome = %q, want %q", result.Outcome, OutcomeSuccess)
		}
		if result.Latency <= 0 {
			t.Errorf("Latency should be positive, got %v", result.Latency)
		}
	})

	t.Run("refused — nothing listening on port", func(t *testing.T) {
		// port 1 is reserved and nothing listens on it
		// on Linux this reliably returns ECONNREFUSED
		result := prober.Probe("127.0.0.1", 1, 3*time.Second)

		if result.Outcome != OutcomeRefused {
			t.Errorf("Outcome = %q, want %q", result.Outcome, OutcomeRefused)
		}
	})

	t.Run("timeout — unroutable address", func(t *testing.T) {
		// 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — reserved, not routable
		// connections to it will always timeout
		result := prober.Probe("192.0.2.1", 443, 1*time.Second)

		if result.Outcome != OutcomeTimeout {
			t.Errorf("Outcome = %q, want %q", result.Outcome, OutcomeTimeout)
		}
	})
}

func TestClassifyError(t *testing.T) {
	timeout := 5 * time.Second

	tests := []struct {
		name     string
		err      error
		latency  time.Duration
		timeout  time.Duration
		expected Outcome
	}{
		{
			name:     "net.Error with Timeout() true — timeout",
			err:      &mockTimeoutError{},
			latency:  5 * time.Second,
			timeout:  timeout,
			expected: OutcomeTimeout,
		},
		{
			name: "ECONNREFUSED — refused",
			err: &net.OpError{
				Op: "dial",
				Err: &os.SyscallError{
					Syscall: "connect",
					Err:     syscall.ECONNREFUSED,
				},
			},
			latency:  2 * time.Millisecond,
			timeout:  timeout,
			expected: OutcomeRefused,
		},
		{
			name:     "unknown error — latency near timeout — timeout",
			err:      errors.New("unknown network error"),
			latency:  4*time.Second + 950*time.Millisecond,
			timeout:  timeout,
			expected: OutcomeTimeout,
		},
		{
			name:     "unknown error — latency far from timeout — default timeout",
			err:      errors.New("unknown network error"),
			latency:  100 * time.Millisecond,
			timeout:  timeout,
			expected: OutcomeTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyError(tt.err, tt.latency, tt.timeout)
			if got != tt.expected {
				t.Errorf("classifyError() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestIsConnectionRefused(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name: "ECONNREFUSED wrapped in OpError and SyscallError",
			err: &net.OpError{
				Op: "dial",
				Err: &os.SyscallError{
					Syscall: "connect",
					Err:     syscall.ECONNREFUSED,
				},
			},
			expected: true,
		},
		{
			name: "ECONNREFUSED directly on OpError",
			err: &net.OpError{
				Op:  "dial",
				Err: syscall.ECONNREFUSED,
			},
			expected: true,
		},
		{
			name: "different syscall error — not refused",
			err: &net.OpError{
				Op:  "dial",
				Err: syscall.ETIMEDOUT,
			},
			expected: false,
		},
		{
			name:     "plain error — not a net.OpError",
			err:      errors.New("connection refused"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isConnectionRefused(tt.err)
			if got != tt.expected {
				t.Errorf("isConnectionRefused() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// mockTimeoutError implements net.Error for testing timeout classification.
type mockTimeoutError struct{}

func (e *mockTimeoutError) Error() string   { return "mock timeout" }
func (e *mockTimeoutError) Timeout() bool   { return true }
func (e *mockTimeoutError) Temporary() bool { return true }
