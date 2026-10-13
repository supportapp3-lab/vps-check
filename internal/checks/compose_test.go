package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vps-check/internal/model"
	"vps-check/internal/report"
	"vps-check/internal/runner"
)

func TestComposePortForms(t *testing.T) {
	tests := []struct {
		name, entry string
		status      model.Status
		value       string
	}{
		{"short implicit IP", `"8080:80"`, model.WARN, "8080:80"},
		{"short IPv4 all", `"0.0.0.0:8080:80"`, model.WARN, "0.0.0.0:8080:80"},
		{"short IPv6 all", `"[::]:8080:80"`, model.WARN, "[::]:8080:80"},
		{"short range", `"8000-8010:8000-8010"`, model.WARN, "8000-8010:8000-8010"},
		{"short random host port", `"80"`, model.WARN, "80"},
		{"short integer", `3000`, model.WARN, "3000"},
		{"short udp", `"8080:80/udp"`, model.WARN, "8080:80/udp"},
		{"PostgreSQL", `"5432:1234"`, model.HIGH, "5432:1234"},
		{"MySQL", `"0.0.0.0:3306:1234"`, model.HIGH, "3306"},
		{"Redis", `"[::]:6379:1234"`, model.HIGH, "6379"},
		{"MongoDB", `"27017:1234"`, model.HIGH, "27017"},
		{"datastore in host range", `"5430-5440:8000-8010"`, model.HIGH, "5430-5440"},
		{"target alone is not host severity", `"15432:5432"`, model.WARN, "15432:5432"},
		{"random host DB target", `"5432"`, model.WARN, "5432"},
		{"long implicit IP", `{target: 80, published: "8080"}`, model.WARN, "8080"},
		{"long IPv4 all", `{target: 80, published: 8080, host_ip: "0.0.0.0"}`, model.WARN, "0.0.0.0"},
		{"long IPv6 all", `{target: 80, published: "8080", host_ip: "::"}`, model.WARN, "::"},
		{"long datastore", `{target: 80, published: "6379"}`, model.HIGH, "6379"},
		{"long range", `{target: 80, published: "3300-3310"}`, model.HIGH, "3300-3310"},
		{"IPv4 loopback", `"127.0.0.1:8080:80"`, model.PASS, ""},
		{"IPv6 loopback", `"[::1]:8080:80"`, model.PASS, ""},
		{"long IPv4 loopback", `{target: 80, published: "8080", host_ip: "127.0.0.1"}`, model.PASS, ""},
		{"long IPv6 loopback", `{target: 80, published: "8080", host_ip: "::1"}`, model.PASS, ""},
		{"long unpublished", `{target: 80}`, model.PASS, ""},
		{"specific host address", `"192.0.2.10:8080:80"`, model.PASS, ""},
		{"short variable", `"${PORT}:80"`, model.INFO, "${PORT}"},
		{"long published variable", `{target: 80, published: "${PORT}"}`, model.INFO, "${PORT}"},
		{"long host variable", `{target: 80, published: "8080", host_ip: "${HOST_IP}"}`, model.INFO, "${HOST_IP}"},
		{"long target variable", `{target: "${TARGET}", published: "8080"}`, model.INFO, "${TARGET}"},
		{"invalid port", `"70000:80"`, model.INFO, "70000"},
		{"invalid range", `"9000-8000:80"`, model.INFO, "9000-8000"},
		{"unsupported scalar", `true`, model.INFO, "true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte("services:\n  demo:\n    ports:\n      - " + tt.entry + "\n")
			got := Compose(fakeRunner{files: map[string][]byte{"example.yaml": data}}, []string{"example.yaml"})
			if len(got) != 1 || got[0].ID != "DKR-002" || got[0].Status != tt.status {
				t.Fatalf("got %+v, want one %s finding", got, tt.status)
			}
			if tt.status != model.PASS {
				for _, value := range []string{"example.yaml", "Service: demo", tt.value} {
					if !strings.Contains(got[0].Evidence, value) {
						t.Errorf("evidence missing %q: %s", value, got[0].Evidence)
					}
				}
				if !strings.Contains(got[0].Remediation, "127.0.0.1:") {
					t.Errorf("missing loopback example: %+v", got[0])
				}
			}
		})
	}
}

func TestComposeServiceForms(t *testing.T) {
	tests := []struct {
		name, service string
		status        model.Status
	}{
		{"host network", "network_mode: host", model.INFO},
		{"variable network", `network_mode: "${MODE}"`, model.INFO},
		{"expose only", "expose: [5432]", model.PASS},
		{"no ports", "image: fictional/demo", model.PASS},
		{"empty ports", "ports: []", model.PASS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compose(fakeRunner{files: map[string][]byte{"example.yaml": []byte("services:\n  demo:\n    " + tt.service + "\n")}}, []string{"example.yaml"})
			if len(got) != 1 || got[0].Status != tt.status {
				t.Fatalf("unexpected findings: %+v", got)
			}
		})
	}
}

type composeFilesRunner struct {
	fakeRunner
	readPaths []string
	errors    map[string]error
}

func (r *composeFilesRunner) ReadFile(path string) ([]byte, error) {
	r.readPaths = append(r.readPaths, path)
	if err := r.errors[path]; err != nil {
		return nil, err
	}
	if data, ok := r.files[path]; ok {
		return data, nil
	}
	return nil, fs.ErrNotExist
}

func TestComposeFileSelection(t *testing.T) {
	data := []byte("services:\n  demo:\n    ports: [\"8080:80\"]\n")
	for _, name := range defaultComposePaths {
		t.Run(name, func(t *testing.T) {
			r := &composeFilesRunner{fakeRunner: fakeRunner{files: map[string][]byte{name: data}}}
			got := Compose(r, nil)
			if len(got) != 1 || got[0].Status != model.WARN || !strings.Contains(got[0].Evidence, name) {
				t.Fatalf("default lookup failed: %+v", got)
			}
		})
	}
	r := &composeFilesRunner{}
	if got := Compose(r, nil); len(got) != 1 || got[0].Status != model.SKIP {
		t.Fatalf("missing default files: %+v", got)
	}
	r = &composeFilesRunner{fakeRunner: fakeRunner{files: map[string][]byte{"one.yaml": data, "two.yaml": data, "compose.yaml": data}}}
	got := Compose(r, []string{"one.yaml", "two.yaml"})
	if len(got) != 2 || strings.Join(r.readPaths, ",") != "one.yaml,two.yaml" {
		t.Fatalf("explicit paths not used independently: %+v / %v", got, r.readPaths)
	}
	r = &composeFilesRunner{fakeRunner: fakeRunner{files: map[string][]byte{"compose.yaml": data, "compose.yml": data}}}
	if got := Compose(r, nil); len(got) != 2 {
		t.Fatalf("all matching defaults should be checked: %+v", got)
	}
}

func TestComposeUnreadableAndInvalidFiles(t *testing.T) {
	tests := []struct{ name, data string }{
		{"broken YAML", "services: ["},
		{"empty YAML", ""},
		{"two documents", "services: {}\n---\nservices: {}\n"},
		{"duplicate service", "services:\n  demo: {}\n  demo: {}\n"},
		{"ports not a list", "services:\n  demo:\n    ports: true\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compose(fakeRunner{files: map[string][]byte{"example.yaml": []byte(tt.data)}}, []string{"example.yaml"})
			if len(got) != 1 || got[0].Status != model.SKIP {
				t.Fatalf("expected SKIP, got %+v", got)
			}
		})
	}
	for _, err := range []error{fs.ErrNotExist, fs.ErrPermission} {
		r := &composeFilesRunner{errors: map[string]error{"example.yaml": err}}
		if got := Compose(r, []string{"example.yaml"}); len(got) != 1 || got[0].Status != model.SKIP {
			t.Fatalf("explicit unreadable file: %+v", got)
		}
	}
	r := &composeFilesRunner{errors: map[string]error{"compose.yaml": fs.ErrPermission}}
	if got := Compose(r, nil); len(got) != 1 || !strings.Contains(got[0].Evidence, "compose.yaml") {
		t.Fatalf("default permission failure hidden: %+v", got)
	}
}

func TestComposeAnchorsAndServiceOrder(t *testing.T) {
	data := []byte("x-default: &default\n  ports: [\"8080:80\"]\nservices:\n  zebra:\n    <<: *default\n  alpha:\n    ports: [\"5432:80\", \"127.0.0.1:8080:80\"]\n")
	got := Compose(fakeRunner{files: map[string][]byte{"example.yaml": data}}, []string{"example.yaml"})
	if len(got) != 2 || got[0].Status != model.HIGH || !strings.Contains(got[0].Evidence, "alpha") || !strings.Contains(got[1].Evidence, "zebra") {
		t.Fatalf("unexpected merged/ordered findings: %+v", got)
	}
}

func TestComposeDoesNotModifyInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compose.yaml")
	data := []byte("# fictional fixture\nservices:\n  demo:\n    ports: [\"8080:80\"]\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if got := Compose(runner.System{}, []string{path}); len(got) != 1 || got[0].Status != model.WARN {
		t.Fatalf("unexpected findings: %+v", got)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("Compose changed the input file")
	}
}

func TestComposeUsesExistingReportFormats(t *testing.T) {
	data := []byte("services:\n  demo:\n    network_mode: host\n    ports: [\"5432:80\", \"${PORT}:80\"]\n")
	findings := Compose(fakeRunner{files: map[string][]byte{"example.yaml": data}}, []string{"example.yaml"})
	rep := model.Report{Version: "0.1.0", Findings: findings}
	var text, encoded bytes.Buffer
	if err := report.Terminal(&text, rep, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[HIGH]", "[INFO]", "Service: demo", "5432:80", "${PORT}", "network_mode: host", "127.0.0.1:"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("terminal output missing %q: %s", want, text.String())
		}
	}
	if err := report.JSON(&encoded, rep); err != nil {
		t.Fatal(err)
	}
	var decoded model.Report
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil || fmt.Sprint(decoded.Findings) != fmt.Sprint(findings) {
		t.Fatal("JSON did not retain Compose findings")
	}
}

func TestAllIncludesComposeWithoutDocker(t *testing.T) {
	r := fakeRunner{files: map[string][]byte{"example.yaml": []byte("services:\n  demo:\n    ports: [\"8080:80\"]\n")}}
	for _, finding := range All(context.Background(), r, "Unknown", "example.yaml") {
		if finding.ID == "DKR-002" && finding.Status == model.WARN {
			return
		}
	}
	t.Fatal("DKR-002 was not included without Docker installed")
}
