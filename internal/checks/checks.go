package checks

import (
	"context"

	"vps-check/internal/model"
	"vps-check/internal/runner"
)

func All(ctx context.Context, r runner.Runner, osName string) []model.Finding {
	findings := []model.Finding{}
	findings = append(findings, Network(ctx, r)...)
	findings = append(findings, Docker(ctx, r)...)
	findings = append(findings, SSH(ctx, r)...)
	findings = append(findings, Firewall(ctx, r)...)
	findings = append(findings, Web(ctx, r)...)
	findings = append(findings, Updates(ctx, r, osName)...)
	return findings
}
