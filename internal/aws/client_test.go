package aws

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/smithy-go"
)

// mockAPIError implements smithy.APIError for testing.
type mockAPIError struct {
	code    string
	message string
	fault   smithy.ErrorFault
}

func (e *mockAPIError) Error() string                 { return e.code + ": " + e.message }
func (e *mockAPIError) ErrorCode() string             { return e.code }
func (e *mockAPIError) ErrorMessage() string          { return e.message }
func (e *mockAPIError) ErrorFault() smithy.ErrorFault { return e.fault }

func TestIsAccessDenied(t *testing.T) {
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
			name:     "UnauthorizedOperation",
			err:      &mockAPIError{code: "UnauthorizedOperation"},
			expected: true,
		},
		{
			name:     "AccessDenied",
			err:      &mockAPIError{code: "AccessDenied"},
			expected: true,
		},
		{
			name:     "AuthFailure",
			err:      &mockAPIError{code: "AuthFailure"},
			expected: true,
		},
		{
			name:     "InvalidClientTokenId",
			err:      &mockAPIError{code: "InvalidClientTokenId"},
			expected: true,
		},
		{
			name:     "unrelated AWS error",
			err:      &mockAPIError{code: "InvalidInstanceID.NotFound"},
			expected: false,
		},
		{
			name:     "plain non-AWS error",
			err:      errors.New("connection refused"),
			expected: false,
		},
		{
			name:     "wrapped access denied",
			err:      fmt.Errorf("outer: %w", &mockAPIError{code: "AccessDenied"}),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAccessDenied(tt.err)
			if got != tt.expected {
				t.Errorf("isAccessDenied() = %v, want %v", got, tt.expected)
			}
		})
	}
}
