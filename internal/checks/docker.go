package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"vps-check/internal/model"
	"vps-check/internal/runner"
)

var portMapping = regexp.MustCompile(`(?i)(\[[^]]+\]|[^,\s]+):(\d+)->(\d+)/(tcp|udp)`)

type DockerBinding struct{ Address, HostPort, ContainerPort, Protocol string }

func ParseDockerPorts(value string) []DockerBinding {
	var result []DockerBinding
	for _, m := range portMapping.FindAllStringSubmatch(value, -1) {
		result = append(result, DockerBinding{Address: strings.Trim(m[1], "[]"), HostPort: m[2], ContainerPort: m[3], Protocol: strings.ToLower(m[4])})
	}
	return result
}

func Docker(ctx context.Context, r runner.Runner) []model.Finding {
	if _, err := r.LookPath("docker"); err != nil {
		return []model.Finding{{ID: "DKR-001", Status: model.INFO, Title: "Docker is not installed", Explanation: "Docker was not found; container port bindings were not applicable."}}
	}
	out, stderr, err := r.Run(ctx, "docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
	if err != nil {
		reason := strings.TrimSpace(stderr)
		if strings.Contains(strings.ToLower(reason+err.Error()), "permission denied") || strings.Contains(strings.ToLower(reason+err.Error()), "permission") {
			return []model.Finding{{ID: "DKR-001", Status: model.SKIP, Title: "Docker port bindings could not be checked", Evidence: reason, Explanation: "Permission to access the Docker daemon was denied. Try running vps-check with appropriate Docker access."}}
		}
		return []model.Finding{{ID: "DKR-001", Status: model.SKIP, Title: "Docker port bindings could not be checked", Evidence: reason, Explanation: "Docker is present, but its container list could not be read."}}
	}
	var findings []model.Finding
	for _, line := range strings.Split(out, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(fields) != 2 {
			continue
		}
		for _, b := range ParseDockerPorts(fields[1]) {
			if addressScope(b.Address) != "all" {
				continue
			}
			binding := fmt.Sprintf("%s:%s -> %s/%s", b.Address, b.HostPort, b.ContainerPort, b.Protocol)
			findings = append(findings, model.Finding{ID: "DKR-001", Status: model.WARN, Title: "Docker port is bound to all interfaces", Evidence: fmt.Sprintf("Container: %s\nBinding: %s", fields[0], binding), Explanation: "This does not necessarily mean the port is reachable from the Internet. Firewall or provider-level rules may block it.", Remediation: "If this service is only accessed through a local reverse proxy, consider binding it to 127.0.0.1:" + b.HostPort + ":" + b.ContainerPort + "."})
		}
	}
	if len(findings) == 0 {
		findings = append(findings, model.Finding{ID: "DKR-001", Status: model.PASS, Title: "No Docker ports bound to all interfaces detected", Explanation: "Docker container port mappings were checked."})
	}
	return findings
}
