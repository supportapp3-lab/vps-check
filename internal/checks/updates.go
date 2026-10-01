package checks

import (
	"context"
	"regexp"
	"strings"

	"vps-check/internal/model"
	"vps-check/internal/runner"
)

var aptSetting = regexp.MustCompile(`(?mi)^\s*APT::Periodic::Unattended-Upgrade\s+"?([^";]+)"?\s*;`)

func Updates(ctx context.Context, r runner.Runner, osName string) []model.Finding {
	if !strings.EqualFold(osName, "Ubuntu") {
		return []model.Finding{{ID: "UPD-001", Status: model.INFO, Title: "Automatic security updates check applies to Ubuntu", Explanation: "This v0.1 check reads Ubuntu apt settings only."}}
	}
	if _, err := r.LookPath("apt-config"); err != nil {
		return []model.Finding{{ID: "UPD-001", Status: model.SKIP, Title: "Automatic security updates could not be checked", Explanation: "apt-config is not available."}}
	}
	out, stderr, err := r.Run(ctx, "apt-config", "dump")
	if err != nil {
		return []model.Finding{{ID: "UPD-001", Status: model.SKIP, Title: "Automatic security updates could not be checked", Evidence: strings.TrimSpace(stderr), Explanation: "Could not read apt configuration."}}
	}
	if _, err := r.LookPath("dpkg-query"); err != nil {
		return []model.Finding{{ID: "UPD-001", Status: model.SKIP, Title: "Automatic security updates could not be confirmed", Explanation: "dpkg-query is not available, so the unattended-upgrades package could not be confirmed."}}
	}
	pkgStatus, pkgStderr, err := r.Run(ctx, "dpkg-query", "-W", "-f=${db:Status-Status}", "unattended-upgrades")
	if err != nil {
		return []model.Finding{{ID: "UPD-001", Status: model.SKIP, Title: "Automatic security updates could not be confirmed", Evidence: strings.TrimSpace(pkgStderr), Explanation: "Could not confirm whether unattended-upgrades is installed."}}
	}
	if strings.TrimSpace(pkgStatus) != "installed" {
		return []model.Finding{{ID: "UPD-001", Status: model.WARN, Title: "unattended-upgrades is not installed", Evidence: "Package status: " + strings.TrimSpace(pkgStatus), Explanation: "The unattended-upgrades package is not installed, so the apt schedule alone cannot apply automatic security updates.", Remediation: "Review whether unattended-upgrades should be installed and enabled for this server."}}
	}
	m := aptSetting.FindStringSubmatch(out)
	if len(m) == 0 {
		return []model.Finding{{ID: "UPD-001", Status: model.SKIP, Title: "Automatic security updates could not be determined", Explanation: "apt-config did not report the unattended-upgrade schedule."}}
	}
	value := strings.TrimSpace(m[1])
	if value == "1" || strings.EqualFold(value, "true") {
		return []model.Finding{{ID: "UPD-001", Status: model.PASS, Title: "Automatic security updates are scheduled", Evidence: "APT::Periodic::Unattended-Upgrade " + value, Explanation: "apt configuration enables unattended upgrades. This check does not verify that updates have recently succeeded."}}
	}
	return []model.Finding{{ID: "UPD-001", Status: model.WARN, Title: "Automatic security updates are not scheduled", Evidence: "APT::Periodic::Unattended-Upgrade " + value, Explanation: "The apt unattended-upgrade schedule appears disabled.", Remediation: "Review unattended-upgrades and apt periodic settings to decide whether automatic security updates should be enabled."}}
}
