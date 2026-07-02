# Adding Analysis Passes

## Pass interface

Every pass implements the `Pass` interface from `pkg/passes/pass.go`:

```go
type Pass interface {
    Name() string
    Run(ctx *Context) error
}
```

The `Context` provides access to:

- `Program`: the loaded SSA program with call graph
- `Platform`: the platform knowledge database
- `Result`: the shared result struct to append findings to

## Creating a new pass

1. Create a new package under `pkg/passes/yourpass/`
2. Implement the `Pass` interface
3. Register it in `cmd/trust-flow-analyzer/main.go`

### Example skeleton

```go
package yourpass

import (
    "github.com/ugiordan/trust-flow-analyzer/pkg/loader"
    "github.com/ugiordan/trust-flow-analyzer/pkg/passes"
)

type Pass struct{}

func (p *Pass) Name() string { return "yourpass" }

func (p *Pass) Run(ctx *passes.Context) error {
    for _, fn := range loader.SortedModuleFunctions(ctx.Program) {
        // Your analysis logic here
    }
    return nil
}
```

## Key patterns

### Use `SortedModuleFunctions` for determinism

Always iterate functions via `loader.SortedModuleFunctions(prog)` instead of ranging over `prog.CallGraph.Nodes` directly. The sorted function list ensures deterministic output.

### Use `RelativePath` for file paths

Always use `loader.RelativePath(file, prog.ModulePath)` instead of `filepath.Base(file)` to preserve directory context in output.

### Use the call graph for interprocedural analysis

```go
node := prog.CallGraph.Nodes[fn]
if node == nil {
    return
}
for _, edge := range node.Out {
    callee := edge.Callee.Func
    // trace forward calls
}
for _, edge := range node.In {
    caller := edge.Caller.Func
    // find who calls this function
}
```

### Add results to the shared `AnalysisResult`

Each pass appends to the relevant slice in `ctx.Result`:

```go
ctx.Result.YourFindings = append(ctx.Result.YourFindings, finding)
```

Remember to sort the results for determinism before returning.

## Adding synthesis rules

If your pass produces findings that should be cross-referenced with other passes, add a detection function in `pkg/synthesis/synthesis.go` and call it from `Synthesize()`.
