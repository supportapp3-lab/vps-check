package checks

import (
	"context"
	"strings"

	"vps-check/internal/model"
	"vps-check/internal/runner"
)

type SSHConfig struct{ PasswordAuthentication, PermitRootLogin string }

// ParseSSHDConfig parses sshd -T's effective key/value output (not sshd_config source text).
func ParseSSHDConfig(output string) SSHConfig {
	var c SSHConfig
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(strings.ToLower(line))
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "passwordauthentication":
			c.PasswordAuthentication = f[1]
		case "permitrootlogin":
			c.PermitRootLogin = f[1]
		}
	}
	return c
}

func SSH(ctx context.Context, r runner.Runner) []model.Finding {
	if _, err := r.LookPath("sshd"); err != nil {
		return []model.Finding{{ID: "SSH-001", Status: model.INFO, Title: "OpenSSH server was not detected", Explanation: "sshd was not found; SSH server settings were not checked."}, {ID: "SSH-002", Status: model.INFO, Title: "OpenSSH server was not detected", Explanation: "sshd was not found; SSH root login settings were not checked."}}
	}
	out, stderr, err := r.Run(ctx, "sshd", "-T")
	if err != nil {
		evidence := strings.TrimSpace(stderr)
		msg := "The effective SSH configuration could not be read, so no setting was inferred."
		if strings.Contains(strings.ToLower(evidence+err.Error()), "permission") {
			msg = "Permission was insufficient to read the effective SSH configuration. Try: sudo vps-check"
		}
		return []model.Finding{
			{ID: "SSH-001", Status: model.SKIP, Title: "SSH password authentication could not be checked", Evidence: evidence, Explanation: msg},
			{ID: "SSH-002", Status: model.SKIP, Title: "SSH root login could not be checked", Evidence: evidence, Explanation: msg},
		}
	}
	c := ParseSSHDConfig(out)
	var result []model.Finding
	switch c.PasswordAuthentication {
	case "yes":
		result = append(result, model.Finding{ID: "SSH-001", Status: model.WARN, Title: "SSH password authentication is enabled", Evidence: "PasswordAuthentication yes", Explanation: "SSH accounts may be authenticated with passwords. Passwords can be guessed or reused.", Remediation: "Consider disabling password authentication after confirming key-based access works."})
	case "no":
		result = append(result, model.Finding{ID: "SSH-001", Status: model.PASS, Title: "SSH password authentication is disabled", Evidence: "PasswordAuthentication no"})
	default:
		result = append(result, model.Finding{ID: "SSH-001", Status: model.SKIP, Title: "SSH password authentication could not be determined", Evidence: "sshd -T did not report PasswordAuthentication", Explanation: "The effective value was missing or unrecognized; no setting was inferred."})
	}
	switch c.PermitRootLogin {
	case "yes":
		result = append(result, model.Finding{ID: "SSH-002", Status: model.HIGH, Title: "SSH root login is permitted", Evidence: "PermitRootLogin yes", Explanation: "The root account can log in directly over SSH, including with password authentication if enabled.", Remediation: "Consider setting PermitRootLogin no, or prohibit-password if key-only root access is intentionally required."})
	case "no":
		result = append(result, model.Finding{ID: "SSH-002", Status: model.PASS, Title: "SSH root login is disabled", Evidence: "PermitRootLogin no"})
	case "prohibit-password", "without-password":
		result = append(result, model.Finding{ID: "SSH-002", Status: model.INFO, Title: "SSH root login is limited to non-password authentication", Evidence: "PermitRootLogin " + c.PermitRootLogin, Explanation: "Root login is permitted only through non-password methods such as public keys."})
	case "forced-commands-only":
		result = append(result, model.Finding{ID: "SSH-002", Status: model.INFO, Title: "SSH root login is restricted to forced commands", Evidence: "PermitRootLogin forced-commands-only", Explanation: "Root login is limited to public keys with forced commands configured."})
	default:
		result = append(result, model.Finding{ID: "SSH-002", Status: model.SKIP, Title: "SSH root login could not be determined", Evidence: "sshd -T did not report PermitRootLogin", Explanation: "The effective value was missing or unrecognized; no setting was inferred."})
	}
	return result
}
