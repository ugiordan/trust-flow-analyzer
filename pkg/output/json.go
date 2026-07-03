package output

import (
	"encoding/json"
	"io"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// WriteJSON writes the analysis result as indented JSON.
func WriteJSON(w io.Writer, result *types.AnalysisResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
