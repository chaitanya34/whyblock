package analyzer

import (
	"context"

	"github.com/chaitanya34/whyblock/internal/model"
)

// Analyzer defines the core analysis operations.
type Analyzer interface {
	Check(ctx context.Context, opts model.CheckOptions) (model.CheckResult, error)
	Expose(ctx context.Context, opts model.ExposeOptions) (model.ExposeResult, error)
	Rules(ctx context.Context, opts model.RulesOptions) (model.RulesResult, error)
}

// TODO: implement WhyblockAnalyzer struct that satisfies Analyzer
