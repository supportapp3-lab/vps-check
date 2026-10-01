package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"vps-check/internal/checks"
	"vps-check/internal/model"
	"vps-check/internal/report"
	"vps-check/internal/runner"
)

const version = "0.1.0"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("vps-check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonMode := fs.Bool("json", false, "Write machine-readable JSON")
	verbose := fs.Bool("verbose", false, "Show additional details")
	showVersion := fs.Bool("version", false, "Show version")
	_ = fs.Bool("no-color", false, "Disable color output (default: no color)")
	failOn := fs.String("fail-on", "", "Exit with code 1 at this severity or higher (warn, high)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Printf("vps-check %s\n", version)
		return 0
	}
	threshold := strings.ToLower(strings.TrimSpace(*failOn))
	if threshold != "" && threshold != "warn" && threshold != "high" {
		fmt.Fprintln(os.Stderr, "vps-check: --fail-on must be 'warn' or 'high'")
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "vps-check: unexpected positional arguments")
		return 2
	}
	r := runner.System{}
	osInfo := checks.OSInfo(r)
	findings := checks.All(context.Background(), r, osInfo.Name)
	rep := model.Report{Version: version, OS: osInfo, Timestamp: time.Now().UTC().Format(time.RFC3339), Findings: findings}
	var err error
	if *jsonMode {
		err = report.JSON(os.Stdout, rep)
	} else {
		err = report.Terminal(os.Stdout, rep, *verbose)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vps-check: could not write report:", err)
		return 2
	}
	for _, f := range findings {
		if failsThreshold(f.Status, threshold) {
			return 1
		}
	}
	return 0
}

func failsThreshold(status model.Status, threshold string) bool {
	switch threshold {
	case "high":
		return status == model.HIGH
	case "warn":
		return status == model.WARN || status == model.HIGH
	default:
		return false
	}
}
