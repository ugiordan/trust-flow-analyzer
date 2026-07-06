package passes

import (
	"github.com/ugiordan/trust-flow-analyzer/pkg/ir"
	"github.com/ugiordan/trust-flow-analyzer/pkg/platform"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// ArchComponent represents a component from an architecture-analyzer output.
type ArchComponent struct {
	Name     string   `json:"name"`
	Packages []string `json:"packages"`
}

// ArchContext holds parsed architecture context from an external analyzer.
type ArchContext struct {
	Components []ArchComponent `json:"components"`
}

// Context holds shared state for all analysis passes.
type Context struct {
	Program     *ir.AnalysisProgram
	Platform    *platform.Knowledge
	Result      *types.AnalysisResult
	ArchContext *ArchContext
}

// Pass is the interface that all analysis passes implement.
type Pass interface {
	Name() string
	Run(ctx *Context) error
}
