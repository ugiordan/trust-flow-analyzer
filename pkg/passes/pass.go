package passes

import (
	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/platform"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// Context holds shared state for all analysis passes.
type Context struct {
	Program  *loader.Program
	Platform *platform.Knowledge
	Result   *types.AnalysisResult
}

// Pass is the interface that all analysis passes implement.
type Pass interface {
	Name() string
	Run(ctx *Context) error
}
