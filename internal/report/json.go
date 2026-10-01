package report

import (
	"encoding/json"
	"io"

	"vps-check/internal/model"
)

func JSON(w io.Writer, r model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
