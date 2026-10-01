package checks

import (
	"context"

	"vps-check/internal/model"
	"vps-check/internal/runner"
)

func Web(ctx context.Context, r runner.Runner) []model.Finding {
	services := []struct{ binary, name string }{{"nginx", "Nginx"}, {"caddy", "Caddy"}, {"apache2", "Apache HTTP Server"}, {"httpd", "Apache HTTP Server"}}
	var found []model.Finding
	seen := map[string]bool{}
	for _, s := range services {
		if _, err := r.LookPath(s.binary); err != nil {
			continue
		}
		if seen[s.name] {
			continue
		}
		seen[s.name] = true
		found = append(found, model.Finding{ID: "WEB-001", Status: model.INFO, Title: s.name + " detected", Explanation: "The server executable is available. This check does not verify whether it is configured as a reverse proxy or whether it is running."})
	}
	if len(found) == 0 {
		found = append(found, model.Finding{ID: "WEB-001", Status: model.INFO, Title: "No common reverse proxy detected", Explanation: "Nginx, Caddy, and Apache executables were not found. A reverse proxy is optional and this is not itself a problem."})
	}
	return found
}
