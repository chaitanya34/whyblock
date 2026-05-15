package model

import "time"

// CheckOptions holds the parsed flags for the check command.
type CheckOptions struct {
	InstanceID string
	Port       int
	Proto      string
	From       string
	Timeout    int
	Output     string
	Region     string
	Profile    string
}

// ExposeOptions holds the parsed flags for the expose command.
type ExposeOptions struct {
	InstanceID string
	From       string
	Output     string
	Region     string
	Profile    string
}

// RulesOptions holds the parsed flags for the rules command.
type RulesOptions struct {
	InstanceID string
	Output     string
	Region     string
	Profile    string
}

// TimeoutDuration converts the Timeout int (seconds) to time.Duration.
func (o CheckOptions) TimeoutDuration() time.Duration {
	return time.Duration(o.Timeout) * time.Second
}
