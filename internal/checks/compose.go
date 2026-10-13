package checks

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"vps-check/internal/model"
	"vps-check/internal/runner"
)

var defaultComposePaths = []string{"compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"}

type composeDocument struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	NetworkMode string      `yaml:"network_mode"`
	Ports       []yaml.Node `yaml:"ports"`
}

// Compose reads the supplied files independently. It never invokes Docker,
// expands environment variables, merges files, or writes back to the files.
func Compose(r runner.Runner, paths []string) []model.Finding {
	explicit := len(paths) > 0
	if !explicit {
		paths = defaultComposePaths
	}
	var findings []model.Finding
	for _, path := range paths {
		data, err := r.ReadFile(path)
		if err != nil {
			if !explicit && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			findings = append(findings, composeSkip(path, "The Compose file could not be read.", err))
			continue
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		var document composeDocument
		if err := decoder.Decode(&document); err != nil {
			findings = append(findings, composeSkip(path, "The Compose YAML could not be parsed.", err))
			continue
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			findings = append(findings, composeSkip(path, "Expected one YAML document per Compose file.", err))
			continue
		}
		fileFindings := checkComposeDocument(path, document)
		if len(fileFindings) == 0 {
			fileFindings = []model.Finding{{ID: "DKR-002", Status: model.PASS,
				Title: "No Compose ports bound to all interfaces detected", Evidence: "File: " + path,
				Explanation: "The declared ports in this file were checked without starting containers. This does not verify external reachability or Docker daemon defaults."}}
		}
		findings = append(findings, fileFindings...)
	}
	if len(findings) == 0 {
		findings = []model.Finding{{ID: "DKR-002", Status: model.SKIP, Title: "No Compose file found",
			Explanation: "No compose.yaml, compose.yml, docker-compose.yml, or docker-compose.yaml was found in the current directory. Use --compose <path> to select a file."}}
	}
	return findings
}

func composeSkip(path, explanation string, err error) model.Finding {
	evidence := "File: " + path
	if err != nil {
		evidence += "\nReason: " + err.Error()
	}
	return model.Finding{ID: "DKR-002", Status: model.SKIP, Title: "Compose ports could not be checked", Evidence: evidence, Explanation: explanation}
}

func checkComposeDocument(path string, document composeDocument) []model.Finding {
	services := make([]string, 0, len(document.Services))
	for name := range document.Services {
		services = append(services, name)
	}
	sort.Strings(services)
	var findings []model.Finding
	for _, name := range services {
		service := document.Services[name]
		if service.NetworkMode == "host" || hasComposeVariable(service.NetworkMode) {
			findings = append(findings, composeInfo(path, name, "network_mode: "+service.NetworkMode,
				"Host networking or an unresolved network mode requires a separate review; ports alone cannot describe the bindings."))
		}
		for i := range service.Ports {
			node := &service.Ports[i]
			value := composePortValue(node)
			binding, err := parseComposePort(node)
			if err != nil {
				findings = append(findings, composeInfo(path, name, value, err.Error()))
				continue
			}
			if !binding.published || (binding.hostIP != "" && addressScope(binding.hostIP) != "all") {
				continue
			}
			status := model.WARN
			if containsDatastorePort(binding.hostPort) {
				status = model.HIGH
			}
			hostPort := binding.hostPort
			if hostPort == "" {
				hostPort = "8080"
			}
			remediation := "For local access, use a loopback binding, for example \"127.0.0.1:" + hostPort + ":" + binding.target + binding.protocol + "\". Choose the host port for your application; no file was changed."
			if binding.longForm {
				remediation = "For local access, set host_ip: \"127.0.0.1\" on this long-form port entry. A short-form example is \"127.0.0.1:8080:80\". No file was changed."
			}
			findings = append(findings, model.Finding{ID: "DKR-002", Status: status,
				Title:       "Compose port is configured for all interfaces",
				Evidence:    fmt.Sprintf("File: %s\nService: %s\nValue: %s", path, name, value),
				Explanation: "A missing host IP, 0.0.0.0, or :: publishes on all interfaces by default. This is a configuration warning, not proof of Internet reachability.",
				Remediation: remediation})
		}
	}
	return findings
}

func composeInfo(path, service, value, explanation string) model.Finding {
	evidence := fmt.Sprintf("File: %s\nService: %s\nValue: %s", path, service, value)
	// INFO evidence is hidden by the normal terminal renderer, so keep the
	// relevant service/value in the explanation too, without changing that renderer.
	return model.Finding{ID: "DKR-002", Status: model.INFO, Title: "Compose configuration needs manual review",
		Evidence: evidence, Explanation: fmt.Sprintf("File: %s; Service: %s; Value: %s. %s", path, service, value, explanation),
		Remediation: "Resolve variables or host networking first. An example local port mapping is \"127.0.0.1:8080:80\"."}
}

type composeBinding struct {
	hostIP, hostPort, target, protocol string
	published, longForm                bool
}

func composePortValue(node *yaml.Node) string {
	data, err := yaml.Marshal(node)
	if err != nil {
		return node.Value
	}
	return strings.TrimSpace(string(data))
}

func hasComposeVariable(value string) bool {
	return strings.Contains(value, "$")
}

func parseComposePort(node *yaml.Node) (composeBinding, error) {
	var b composeBinding
	if node.Kind == yaml.AliasNode {
		return parseComposePort(node.Alias)
	}
	if node.Kind == yaml.MappingNode {
		var port struct {
			Published yaml.Node `yaml:"published"`
			HostIP    yaml.Node `yaml:"host_ip"`
			Target    yaml.Node `yaml:"target"`
			Protocol  yaml.Node `yaml:"protocol"`
		}
		if err := node.Decode(&port); err != nil {
			return b, fmt.Errorf("Unrecognized long port syntax: %w", err)
		}
		if port.Published.Kind == 0 {
			return b, nil
		}
		for _, field := range []*yaml.Node{&port.Published, &port.HostIP, &port.Target, &port.Protocol} {
			if field.Kind != 0 && (field.Kind != yaml.ScalarNode || hasComposeVariable(field.Value)) {
				return b, fmt.Errorf("Port fields contain an unresolved variable or unsupported value; no environment interpolation was performed")
			}
		}
		b = composeBinding{hostIP: strings.Trim(port.HostIP.Value, "[]"), hostPort: port.Published.Value,
			target: port.Target.Value, published: true, longForm: true}
		if port.Protocol.Value != "" {
			b.protocol = "/" + port.Protocol.Value
		}
	} else if node.Kind == yaml.ScalarNode && (node.Tag == "!!str" || node.Tag == "!!int") {
		if hasComposeVariable(node.Value) {
			return b, fmt.Errorf("Port contains an unresolved variable; no environment interpolation was performed")
		}
		value, protocol, hasProtocol := strings.Cut(node.Value, "/")
		if hasProtocol {
			b.protocol = "/" + protocol
		}
		if strings.HasPrefix(value, "[") {
			end := strings.Index(value, "]:")
			if end < 0 {
				return b, fmt.Errorf("Unrecognized bracketed IPv6 port mapping")
			}
			b.hostIP, value = value[1:end], value[end+2:]
		}
		parts := strings.Split(value, ":")
		switch len(parts) {
		case 1:
			b.target = parts[0]
		case 2:
			b.hostPort, b.target = parts[0], parts[1]
		case 3:
			if b.hostIP != "" {
				return b, fmt.Errorf("Unrecognized port mapping")
			}
			b.hostIP, b.hostPort, b.target = parts[0], parts[1], parts[2]
		default:
			return b, fmt.Errorf("Unrecognized port mapping; IPv6 addresses must be bracketed")
		}
		b.published = true
	} else {
		return b, fmt.Errorf("Unrecognized Compose port value")
	}
	if !validPortRange(b.target) || (b.hostPort != "" && !validPortRange(b.hostPort)) ||
		(b.protocol != "" && b.protocol != "/tcp" && b.protocol != "/udp") ||
		(b.hostIP != "" && net.ParseIP(b.hostIP) == nil) {
		return b, fmt.Errorf("Port mapping cannot be classified; review its port, protocol, and host IP")
	}
	return b, nil
}

func portRange(value string) (int, int, bool) {
	first, last, isRange := strings.Cut(value, "-")
	start, err := strconv.Atoi(first)
	if err != nil || start < 1 || start > 65535 {
		return 0, 0, false
	}
	end := start
	if isRange {
		end, err = strconv.Atoi(last)
		if err != nil || end < start || end > 65535 {
			return 0, 0, false
		}
	}
	return start, end, true
}

func validPortRange(value string) bool {
	_, _, ok := portRange(value)
	return ok
}

func containsDatastorePort(value string) bool {
	start, end, ok := portRange(value)
	if !ok {
		return false
	}
	for _, port := range []int{5432, 3306, 6379, 27017} {
		if port >= start && port <= end {
			return true
		}
	}
	return false
}
