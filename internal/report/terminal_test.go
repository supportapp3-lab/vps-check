package report

import (
	"bytes"
	"strings"
	"testing"

	"vps-check/internal/model"
)

func TestVerboseIncludesAdditionalEvidenceAndTimestamp(t *testing.T) {
	rep := model.Report{Version: "0.1.0", OS: model.OSInfo{Name: "Ubuntu", Version: "24.04"}, Timestamp: "2026-10-01T00:00:00Z", Findings: []model.Finding{{ID: "DKR-001", Status: model.PASS, Title: "Docker check passed", Evidence: "127.0.0.1:8080"}}}
	var normal, verbose bytes.Buffer
	if err := Terminal(&normal, rep, false); err != nil {
		t.Fatal(err)
	}
	if err := Terminal(&verbose, rep, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(normal.String(), "127.0.0.1:8080") || strings.Contains(normal.String(), "Timestamp:") {
		t.Fatal("default output unexpectedly included verbose details")
	}
	if !strings.Contains(verbose.String(), "127.0.0.1:8080") || !strings.Contains(verbose.String(), "Timestamp:") {
		t.Fatal("verbose output did not include extra details")
	}
}

func TestLoopbackListenerIsHiddenUnlessVerbose(t *testing.T) {
	rep := model.Report{Version: "0.1.0", OS: model.OSInfo{Name: "Ubuntu", Version: "22.04"}, Findings: []model.Finding{{ID: "NET-001", Status: model.INFO, Title: "Service is listening on loopback only", Evidence: "Port: 53\nProtocols: IPv4\nAddresses: 127.0.0.53%lo", Explanation: "Loopback listener details."}}}
	var normal, verbose bytes.Buffer
	if err := Terminal(&normal, rep, false); err != nil {
		t.Fatal(err)
	}
	if err := Terminal(&verbose, rep, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(normal.String(), "127.0.0.53%lo") || strings.Contains(normal.String(), "loopback only") {
		t.Fatalf("normal output included local-only listener details: %s", normal.String())
	}
	if !strings.Contains(verbose.String(), "Port: 53") || !strings.Contains(verbose.String(), "127.0.0.53%lo") || !strings.Contains(verbose.String(), "loopback only") {
		t.Fatalf("verbose output did not include local-only listener details: %s", verbose.String())
	}
}

func TestAllInterfaceListenerEvidenceIsVisibleInNormalOutput(t *testing.T) {
	rep := model.Report{Version: "0.1.0", Findings: []model.Finding{{ID: "NET-001", Status: model.INFO, Title: "Service is listening on all interfaces", Evidence: "Port: 443\nProtocols: IPv4, IPv6\nAddresses: 0.0.0.0, ::", Explanation: "This service may be externally reachable depending on firewall and network configuration."}}}
	var output bytes.Buffer
	if err := Terminal(&output, rep, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[INFO] Service is listening on all interfaces", "Port: 443", "Protocols: IPv4, IPv6", "Addresses: 0.0.0.0, ::"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("normal output is missing %q", want)
		}
	}
}
