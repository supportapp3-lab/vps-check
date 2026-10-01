package checks

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"vps-check/internal/model"
	"vps-check/internal/runner"
)

type Listener struct {
	Address string
	Port    int
	Scope   string
	Family  string
}

// ParseSSListeners parses `ss -H -ltn` output, keeping only TCP LISTEN rows.
func ParseSSListeners(output string) ([]Listener, error) {
	var listeners []Listener
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] != "LISTEN" {
			continue
		}
		if len(f) < 4 {
			return nil, fmt.Errorf("unexpected ss row: %q", line)
		}
		addr, portText, ok := splitEndpoint(f[3])
		if !ok {
			return nil, fmt.Errorf("unexpected ss local address: %q", f[3])
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return nil, fmt.Errorf("invalid ss port %q", portText)
		}
		listeners = append(listeners, Listener{Address: addr, Port: port, Scope: addressScope(addr), Family: addressFamily(addr)})
	}
	return listeners, nil
}

func splitEndpoint(s string) (string, string, bool) {
	if host, port, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(host, "[]"), port, true
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 || i == len(s)-1 {
		return "", "", false
	}
	return strings.Trim(s[:i], "[]"), s[i+1:], true
}

func addressScope(addr string) string {
	a := ipAddressWithoutZone(strings.Trim(addr, "[]"))
	if a == "*" || a == "0.0.0.0" || a == "::" || a == "[::]" {
		return "all"
	}
	if ip := net.ParseIP(ipAddressWithoutZone(a)); ip != nil && ip.IsLoopback() {
		return "loopback"
	}
	return "specific"
}

func ipAddressWithoutZone(addr string) string {
	host, _, hasZone := strings.Cut(addr, "%")
	if hasZone {
		return host
	}
	return addr
}

func Network(ctx context.Context, r runner.Runner) []model.Finding {
	if _, err := r.LookPath("ss"); err != nil {
		return networkSkip("The ss command is not available.", "")
	}
	out, stderr, err := r.Run(ctx, "ss", "-H", "-ltn")
	if err != nil {
		return networkSkip("Could not read the local TCP listening sockets.", strings.TrimSpace(stderr))
	}
	listeners, err := ParseSSListeners(out)
	if err != nil {
		return networkSkip("The ss output was not in a recognized format.", err.Error())
	}
	var findings []model.Finding
	loopbackOnly := true
	byPort := make(map[int][]Listener)
	for _, l := range listeners {
		byPort[l.Port] = append(byPort[l.Port], l)
		if l.Scope != "loopback" {
			loopbackOnly = false
		}
	}
	ports := make([]int, 0, len(byPort))
	for port := range byPort {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	for _, port := range ports {
		group := byPort[port]
		all := listenersWithScope(group, "all")
		specific := listenersWithScope(group, "specific")
		loopback := listenersWithScope(group, "loopback")
		switch {
		case len(all) > 0:
			findings = append(findings, model.Finding{ID: "NET-001", Status: model.INFO, Title: "Service is listening on all interfaces", Evidence: listenerEvidence(port, all), Explanation: "This service may be externally reachable depending on firewall and network configuration."})
		case len(specific) > 0:
			findings = append(findings, model.Finding{ID: "NET-001", Status: model.INFO, Title: "Service is listening on a specific local IP", Evidence: listenerEvidence(port, specific), Explanation: "This service is bound to a specific local IP. External reachability depends on routing, firewall, and provider network settings."})
		case len(loopback) > 0:
			findings = append(findings, model.Finding{ID: "NET-001", Status: model.INFO, Title: "Service is listening on loopback only", Evidence: listenerEvidence(port, loopback), Explanation: "This listener is bound to local loopback addresses and is not reachable through those addresses from another host."})
		}
	}
	if loopbackOnly {
		findings = append(findings, model.Finding{ID: "NET-001", Status: model.PASS, Title: "No non-loopback TCP listeners detected", Explanation: "TCP listening sockets were checked; listeners were loopback-only or none were present."})
	}

	dbNames := map[int]string{5432: "PostgreSQL", 3306: "MySQL / MariaDB", 6379: "Redis", 27017: "MongoDB"}
	dbSeen := map[int]bool{}
	for _, l := range listeners {
		name, ok := dbNames[l.Port]
		if !ok || l.Scope != "all" || dbSeen[l.Port] {
			continue
		}
		dbSeen[l.Port] = true
		findings = append(findings, model.Finding{ID: "NET-002", Status: model.HIGH, Title: name + " is listening on all interfaces", Evidence: fmt.Sprintf("Port: %d\nAddress: %s", l.Port, l.Address), Explanation: "This datastore may accept connections through any interface. Whether it can be reached externally depends on firewall and network configuration.", Remediation: "If remote access is not needed, bind the datastore to localhost or a private interface and review host and provider firewall rules."})
	}
	if len(dbSeen) == 0 {
		findings = append(findings, model.Finding{ID: "NET-002", Status: model.PASS, Title: "No common datastore is listening on all interfaces", Explanation: "PostgreSQL, MySQL/MariaDB, Redis, and MongoDB listening ports were checked."})
	}
	return findings
}

func listenersWithScope(listeners []Listener, scope string) []Listener {
	var result []Listener
	for _, listener := range listeners {
		if listener.Scope == scope {
			result = append(result, listener)
		}
	}
	return result
}

func listenerEvidence(port int, listeners []Listener) string {
	addressSet := make(map[string]bool)
	familySet := make(map[string]bool)
	for _, listener := range listeners {
		addressSet[listener.Address] = true
		if listener.Family != "" {
			familySet[listener.Family] = true
		}
	}
	addresses := make([]string, 0, len(addressSet))
	for address := range addressSet {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool {
		fi, fj := addressFamily(addresses[i]), addressFamily(addresses[j])
		if fi != fj {
			if fi == "IPv4" {
				return true
			}
			if fj == "IPv4" {
				return false
			}
			return fi < fj
		}
		return addresses[i] < addresses[j]
	})
	var families []string
	if familySet["IPv4"] {
		families = append(families, "IPv4")
	}
	if familySet["IPv6"] {
		families = append(families, "IPv6")
	}
	parts := []string{fmt.Sprintf("Port: %d", port)}
	if len(families) > 0 {
		parts = append(parts, "Protocols: "+strings.Join(families, ", "))
	}
	parts = append(parts, "Addresses: "+strings.Join(addresses, ", "))
	return strings.Join(parts, "\n")
}

func addressFamily(addr string) string {
	if ip := net.ParseIP(ipAddressWithoutZone(strings.Trim(addr, "[]"))); ip != nil {
		if ip.To4() != nil {
			return "IPv4"
		}
		return "IPv6"
	}
	return ""
}

func networkSkip(explanation, evidence string) []model.Finding {
	return []model.Finding{
		{ID: "NET-001", Status: model.SKIP, Title: "Listening ports could not be checked", Evidence: evidence, Explanation: explanation},
		{ID: "NET-002", Status: model.SKIP, Title: "Datastore listeners could not be checked", Evidence: evidence, Explanation: explanation},
	}
}
