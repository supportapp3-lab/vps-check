package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"vps-check/internal/model"
)

type fakeRunner struct {
	paths   map[string]bool
	outputs map[string]string
	errors  map[string]error
	stderr  map[string]string
	files   map[string][]byte
}

func (f fakeRunner) Run(_ context.Context, n string, args ...string) (string, string, error) {
	k := n + " " + strings.Join(args, " ")
	return f.outputs[k], f.stderr[k], f.errors[k]
}
func (f fakeRunner) LookPath(n string) (string, error) {
	if f.paths[n] {
		return "/fake/" + n, nil
	}
	return "", errors.New("not found")
}
func (f fakeRunner) ReadFile(n string) ([]byte, error) {
	b, ok := f.files[n]
	if !ok {
		return nil, errors.New("not found")
	}
	return b, nil
}

func TestParseSSListeners(t *testing.T) {
	got, err := ParseSSListeners("LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\nLISTEN 0 128 [::]:6379 [::]:*\nLISTEN 0 128 [::1]:22 [::]:*\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d listeners", len(got))
	}
	want := []string{"loopback", "all", "all", "loopback"}
	for i, v := range want {
		if got[i].Scope != v {
			t.Errorf("listener %d scope %q, want %q", i, got[i].Scope, v)
		}
	}
	if got[1].Family != "IPv4" || got[2].Family != "IPv6" {
		t.Fatalf("unexpected listener address families: %+v", got)
	}
}
func TestParseSSUnexpected(t *testing.T) {
	if _, err := ParseSSListeners("LISTEN broken"); err == nil {
		t.Fatal("expected malformed row error")
	}
	if _, err := ParseSSListeners("LISTEN 0 1 invalid 0.0.0.0:*"); err == nil {
		t.Fatal("expected malformed endpoint error")
	}
}

func TestAddressScopeHandlesInterfaceZones(t *testing.T) {
	tests := []struct {
		address string
		want    string
	}{
		{"127.0.0.53%lo", "loopback"},
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"::1%lo", "loopback"},
		{"fe80::1%eth0", "specific"},
	}
	for _, tt := range tests {
		if got := addressScope(tt.address); got != tt.want {
			t.Errorf("addressScope(%q) = %q, want %q", tt.address, got, tt.want)
		}
	}
}

func TestNetworkKeepsZonedLoopbackAsLoopbackFinding(t *testing.T) {
	r := fakeRunner{paths: map[string]bool{"ss": true}, outputs: map[string]string{"ss -H -ltn": "LISTEN 0 10 127.0.0.53%lo:53 0.0.0.0:*\n"}}
	var loopback *model.Finding
	for _, f := range Network(context.Background(), r) {
		if f.ID == "NET-001" && f.Title == "Service is listening on loopback only" {
			finding := f
			loopback = &finding
		}
	}
	if loopback == nil {
		t.Fatal("loopback-only finding was not produced")
	}
	if !strings.Contains(loopback.Evidence, "Port: 53") || !strings.Contains(loopback.Evidence, "127.0.0.53%lo") {
		t.Fatalf("original zoned address was not retained: %+v", loopback)
	}
}

func TestNetworkDatabaseAllInterfaces(t *testing.T) {
	r := fakeRunner{paths: map[string]bool{"ss": true}, outputs: map[string]string{"ss -H -ltn": "LISTEN 0 10 0.0.0.0:5432 0.0.0.0:*\nLISTEN 0 10 [::]:6379 [::]:*\nLISTEN 0 10 127.0.0.1:27017 0.0.0.0:*\n"}}
	got := Network(context.Background(), r)
	n := 0
	for _, f := range got {
		if f.ID == "NET-002" {
			n++
			if f.Status != "high" {
				t.Errorf("status=%s", f.Status)
			}
		}
	}
	if n != 2 {
		t.Fatalf("got %d database warnings, want PostgreSQL and Redis", n)
	}
}

func TestNetworkSkipsBothChecksWhenSSUnavailable(t *testing.T) {
	got := Network(context.Background(), fakeRunner{})
	if len(got) != 2 || got[0].ID != "NET-001" || got[1].ID != "NET-002" || got[0].Status != "skip" || got[1].Status != "skip" {
		t.Fatalf("unexpected findings when ss is unavailable: %+v", got)
	}
}

func TestNetworkPassesDatastoreCheckWhenNoKnownDatastoreIsBoundAll(t *testing.T) {
	r := fakeRunner{paths: map[string]bool{"ss": true}, outputs: map[string]string{"ss -H -ltn": "LISTEN 0 10 127.0.0.1:5432 0.0.0.0:*\n"}}
	for _, f := range Network(context.Background(), r) {
		if f.ID == "NET-002" {
			if f.Status != "pass" {
				t.Fatalf("NET-002 status=%s", f.Status)
			}
			return
		}
	}
	t.Fatal("NET-002 finding was missing")
}

func TestNetworkCombinesIPv4AndIPv6AllInterfaceListenersAsInfo(t *testing.T) {
	r := fakeRunner{paths: map[string]bool{"ss": true}, outputs: map[string]string{"ss -H -ltn": "LISTEN 0 10 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 10 [::]:443 [::]:*\n"}}
	var gotPort []model.Finding
	for _, f := range Network(context.Background(), r) {
		if f.ID == "NET-001" && strings.Contains(f.Evidence, "Port: 443") {
			gotPort = append(gotPort, f)
		}
	}
	if len(gotPort) != 1 {
		t.Fatalf("got %d findings for port 443, want one", len(gotPort))
	}
	f := gotPort[0]
	if f.Status != model.INFO || f.Title != "Service is listening on all interfaces" {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if !strings.Contains(f.Evidence, "Protocols: IPv4, IPv6") || !strings.Contains(f.Evidence, "Addresses: 0.0.0.0, ::") {
		t.Fatalf("IPv4/IPv6 addresses were not combined: %q", f.Evidence)
	}
}

func TestDockerBindings(t *testing.T) {
	got := ParseDockerPorts("127.0.0.1:4000->4000/tcp, 0.0.0.0:4001->4001/tcp, [::]:4002->4002/tcp, :::4004->4004/tcp, 4003/tcp")
	if len(got) != 4 {
		t.Fatalf("got %d bindings", len(got))
	}
	if addressScope(got[0].Address) != "loopback" || addressScope(got[1].Address) != "all" || addressScope(got[2].Address) != "all" || addressScope(got[3].Address) != "all" {
		t.Fatalf("unexpected scopes: %+v", got)
	}
}
func TestDockerAbsentAndPermissionDenied(t *testing.T) {
	if got := Docker(context.Background(), fakeRunner{}); got[0].Status != "info" {
		t.Fatalf("absent docker status=%s", got[0].Status)
	}
	r := fakeRunner{paths: map[string]bool{"docker": true}, errors: map[string]error{"docker ps --format {{.Names}}\t{{.Ports}}": errors.New("permission denied")}, stderr: map[string]string{"docker ps --format {{.Names}}\t{{.Ports}}": "permission denied"}}
	if got := Docker(context.Background(), r); got[0].Status != "skip" {
		t.Fatalf("permission status=%s", got[0].Status)
	}
}

func TestDockerReportsOnlyAllInterfaceBindings(t *testing.T) {
	r := fakeRunner{paths: map[string]bool{"docker": true}, outputs: map[string]string{"docker ps --format {{.Names}}\t{{.Ports}}": "local-api\t127.0.0.1:4000->4000/tcp\npublic-api\t0.0.0.0:4001->4001/tcp, [::]:4002->4002/tcp\n"}}
	got := Docker(context.Background(), r)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want two all-interface bindings", len(got))
	}
	for _, f := range got {
		if f.Status != "warn" || strings.Contains(f.Evidence, "local-api") {
			t.Errorf("unexpected Docker finding: %+v", f)
		}
	}
}

func TestSSHEffectiveConfig(t *testing.T) {
	for _, tc := range []struct{ input, password, root string }{{"passwordauthentication yes\npermitrootlogin yes", "yes", "yes"}, {"passwordauthentication no\npermitrootlogin no", "no", "no"}, {"passwordauthentication no\npermitrootlogin prohibit-password", "no", "prohibit-password"}} {
		c := ParseSSHDConfig(tc.input)
		if c.PasswordAuthentication != tc.password || c.PermitRootLogin != tc.root {
			t.Errorf("got %+v", c)
		}
	}
}
func TestSSHStatusesAndUnavailable(t *testing.T) {
	r := fakeRunner{paths: map[string]bool{"sshd": true}, outputs: map[string]string{"sshd -T": "passwordauthentication yes\npermitrootlogin yes\n"}}
	got := SSH(context.Background(), r)
	if got[0].Status != "warn" || got[1].Status != "high" {
		t.Fatalf("unexpected statuses: %+v", got)
	}
	r.errors = map[string]error{"sshd -T": errors.New("failed")}
	r.stderr = map[string]string{"sshd -T": "cannot read configuration"}
	got = SSH(context.Background(), r)
	if got[0].Status != "skip" || got[1].Status != "skip" {
		t.Fatalf("unavailable ssh should skip: %+v", got)
	}
	if got[0].Title != "SSH password authentication could not be checked" || got[1].Title != "SSH root login could not be checked" {
		t.Fatalf("SSH skip findings should identify their checks: %+v", got)
	}
	got = SSH(context.Background(), fakeRunner{})
	if got[0].Status != "info" {
		t.Fatalf("missing sshd status=%s", got[0].Status)
	}
}

func TestWebDetectionDoesNotAssertReverseProxyConfiguration(t *testing.T) {
	got := Web(context.Background(), fakeRunner{paths: map[string]bool{"nginx": true}})
	if len(got) != 1 || got[0].Title != "Nginx detected" {
		t.Fatalf("unexpected Nginx finding: %+v", got)
	}
	if strings.Contains(strings.ToLower(got[0].Title), "reverse proxy") || !strings.Contains(got[0].Explanation, "does not verify whether it is configured as a reverse proxy") {
		t.Fatalf("Nginx finding overstates detection: %+v", got[0])
	}
}

func TestUpdates(t *testing.T) {
	r := fakeRunner{paths: map[string]bool{"apt-config": true, "dpkg-query": true}, outputs: map[string]string{"apt-config dump": "APT::Periodic::Unattended-Upgrade \"1\";\n", "dpkg-query -W -f=${db:Status-Status} unattended-upgrades": "installed\n"}}
	if got := Updates(context.Background(), r, "Ubuntu"); got[0].Status != "pass" {
		t.Fatalf("status=%s", got[0].Status)
	}
	r.outputs["apt-config dump"] = "APT::Periodic::Unattended-Upgrade \"0\";\n"
	if got := Updates(context.Background(), r, "Ubuntu"); got[0].Status != "warn" {
		t.Fatalf("status=%s", got[0].Status)
	}
	r.outputs["dpkg-query -W -f=${db:Status-Status} unattended-upgrades"] = ""
	if got := Updates(context.Background(), r, "Ubuntu"); got[0].Status != "warn" || !strings.Contains(got[0].Title, "not installed") {
		t.Fatalf("uninstalled package should warn, got %+v", got[0])
	}
}

func TestFirewallPermissionDeniedIsSkipped(t *testing.T) {
	r := fakeRunner{paths: map[string]bool{"ufw": true}, errors: map[string]error{"ufw status": errors.New("permission denied")}, stderr: map[string]string{"ufw status": "permission denied"}}
	if got := Firewall(context.Background(), r); got[0].Status != "skip" {
		t.Fatalf("permission status=%s", got[0].Status)
	}
	r.paths["nft"] = true
	r.outputs = map[string]string{"ufw status": "Status: inactive\n"}
	r.errors["ufw status"] = nil
	r.errors["nft list ruleset"] = errors.New("permission denied")
	r.stderr["nft list ruleset"] = "permission denied"
	if got := Firewall(context.Background(), r); got[0].Status != "skip" {
		t.Fatalf("unreadable nftables status=%s", got[0].Status)
	}
}
