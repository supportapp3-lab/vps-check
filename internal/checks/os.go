package checks

import (
	"bufio"
	"strings"

	"vps-check/internal/model"
	"vps-check/internal/runner"
)

func OSInfo(r runner.Runner) model.OSInfo {
	b, err := r.ReadFile("/etc/os-release")
	if err != nil {
		return model.OSInfo{Name: "Unknown", Version: ""}
	}
	values := map[string]string{}
	s := bufio.NewScanner(strings.NewReader(string(b)))
	for s.Scan() {
		line := s.Text()
		i := strings.IndexByte(line, '=')
		if i < 1 {
			continue
		}
		k, v := line[:i], strings.TrimSpace(line[i+1:])
		v = strings.Trim(v, "\"'")
		values[k] = v
	}
	name := values["NAME"]
	if name == "" {
		name = values["ID"]
	}
	if name == "" {
		name = "Unknown"
	}
	version := values["VERSION_ID"]
	return model.OSInfo{Name: name, Version: version}
}
