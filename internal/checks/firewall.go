package checks

import (
	"context"
	"strings"

	"vps-check/internal/model"
	"vps-check/internal/runner"
)

func Firewall(ctx context.Context, r runner.Runner) []model.Finding {
	if _, err := r.LookPath("ufw"); err == nil {
		out, stderr, runErr := r.Run(ctx, "ufw", "status")
		if runErr == nil {
			lower := strings.ToLower(out)
			if strings.Contains(lower, "status: active") {
				return []model.Finding{{ID: "FW-001", Status: model.PASS, Title: "UFW host firewall is active", Evidence: "ufw status: active"}}
			}
			if strings.Contains(lower, "status: inactive") {
				if _, nftErr := r.LookPath("nft"); nftErr == nil {
					nftOut, nftStderr, nftRunErr := r.Run(ctx, "nft", "list", "ruleset")
					if nftRunErr != nil {
						return []model.Finding{{ID: "FW-001", Status: model.SKIP, Title: "Host firewall status could not be confirmed", Evidence: strings.TrimSpace(nftStderr), Explanation: "UFW is inactive, and nftables could not be read. Provider-level firewall rules may also apply."}}
					}
					if nftRunErr == nil && strings.TrimSpace(nftOut) != "" {
						return []model.Finding{{ID: "FW-001", Status: model.INFO, Title: "UFW is inactive; nftables rules were found", Evidence: "UFW inactive; nftables returned a ruleset", Explanation: "A host firewall may be configured through nftables. The rules were not evaluated for coverage; provider-level firewall rules may also apply."}}
					}
				}
				return []model.Finding{{ID: "FW-001", Status: model.WARN, Title: "Active host firewall was not confirmed", Evidence: "ufw status: inactive", Explanation: "UFW is inactive. This does not establish that the VPS is unprotected; nftables or provider-level firewall rules may apply.", Remediation: "Review the host firewall and provider network rules to confirm which services should be reachable."}}
			}
			return []model.Finding{{ID: "FW-001", Status: model.SKIP, Title: "Host firewall status could not be determined", Evidence: strings.TrimSpace(out), Explanation: "UFW returned an unrecognized status."}}
		}
		return []model.Finding{{ID: "FW-001", Status: model.SKIP, Title: "UFW status could not be checked", Evidence: strings.TrimSpace(stderr), Explanation: "Could not read UFW status."}}
	}
	if _, err := r.LookPath("nft"); err == nil {
		out, stderr, err := r.Run(ctx, "nft", "list", "ruleset")
		if err == nil && strings.TrimSpace(out) != "" {
			return []model.Finding{{ID: "FW-001", Status: model.INFO, Title: "nftables ruleset detected", Explanation: "A host firewall may be configured through nftables. The rules were not evaluated for coverage; provider-level firewall rules may also apply."}}
		}
		if err != nil {
			return []model.Finding{{ID: "FW-001", Status: model.SKIP, Title: "nftables rules could not be checked", Evidence: strings.TrimSpace(stderr), Explanation: "Permission or command errors prevented reading nftables rules."}}
		}
	}
	return []model.Finding{{ID: "FW-001", Status: model.WARN, Title: "Active host firewall was not confirmed", Explanation: "Neither an active UFW firewall nor a readable nftables ruleset was confirmed. Provider-level firewall rules may still apply."}}
}
