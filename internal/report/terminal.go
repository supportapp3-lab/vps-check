package report

import (
	"fmt"
	"io"
	"strings"

	"vps-check/internal/model"
)

func Terminal(w io.Writer, r model.Report, verbose bool) error {
	if _, err := fmt.Fprintf(w, "VPS Check v%s\n", r.Version); err != nil {
		return err
	}
	if r.OS.Name != "Unknown" {
		osLine := r.OS.Name
		if r.OS.Version != "" {
			osLine += " " + r.OS.Version
		}
		if _, err := fmt.Fprintf(w, "OS: %s\n", osLine); err != nil {
			return err
		}
	}
	if verbose && r.Timestamp != "" {
		if _, err := fmt.Fprintf(w, "Timestamp: %s\n", r.Timestamp); err != nil {
			return err
		}
	}
	counts := map[model.Status]int{}
	for _, f := range r.Findings {
		if !verbose && f.ID == "NET-001" && f.Title == "Service is listening on loopback only" {
			continue
		}
		counts[f.Status]++
		if _, err := fmt.Fprintf(w, "\n[%s] %s\n", strings.ToUpper(string(f.Status)), f.Title); err != nil {
			return err
		}
		showEvidence := verbose || f.Status == model.WARN || f.Status == model.HIGH || f.Status == model.SKIP
		if f.ID == "NET-001" && f.Title != "Service is listening on loopback only" {
			showEvidence = true
		}
		if f.Evidence != "" && showEvidence {
			for _, line := range strings.Split(f.Evidence, "\n") {
				if _, err := fmt.Fprintf(w, "       %s\n", line); err != nil {
					return err
				}
			}
		}
		if f.Explanation != "" {
			if _, err := fmt.Fprintf(w, "       %s\n", f.Explanation); err != nil {
				return err
			}
		}
		if f.Remediation != "" {
			if _, err := fmt.Fprintf(w, "       Suggested next step: %s\n", f.Remediation); err != nil {
				return err
			}
		}
		if verbose && f.Evidence == "" && f.Explanation == "" {
			if _, err := fmt.Fprintln(w, "       No additional details available."); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(w, "\nSummary\nPASS  %d\nINFO  %d\nWARN  %d\nHIGH  %d\nSKIP  %d\n", counts[model.PASS], counts[model.INFO], counts[model.WARN], counts[model.HIGH], counts[model.SKIP])
	return err
}
