package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"vps-check/internal/model"
)

func TestJSONRetainsZonedLoopbackFinding(t *testing.T) {
	rep := model.Report{
		Version: "0.1.0",
		OS:      model.OSInfo{Name: "Ubuntu", Version: "22.04"},
		Findings: []model.Finding{{
			ID:       "NET-001",
			Status:   model.INFO,
			Title:    "Service is listening on loopback only",
			Evidence: "Port: 53\nProtocols: IPv4\nAddresses: 127.0.0.53%lo",
		}},
	}
	var output bytes.Buffer
	if err := JSON(&output, rep); err != nil {
		t.Fatal(err)
	}
	var decoded model.Report
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(decoded.Findings))
	}
	f := decoded.Findings[0]
	if f.ID != "NET-001" || f.Status != model.INFO || f.Title != "Service is listening on loopback only" || f.Evidence != rep.Findings[0].Evidence {
		t.Fatalf("zoned loopback finding was not preserved in JSON: %+v", f)
	}
}
