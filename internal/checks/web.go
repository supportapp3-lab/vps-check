package checks

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"vps-check/internal/model"
	"vps-check/internal/runner"
)

const (
	maxWebRootDepth = 8
	maxWebRootFiles = 10000
)

var (
	webRootDirective    = regexp.MustCompile(`(^|[{};])\s*(root|alias)\s+([^;]+);`)
	nginxInclude        = regexp.MustCompile(`^\s*include\s+([^;]+);`)
	nginxVariable       = regexp.MustCompile(`\$[a-zA-Z_{]`)
	nginxConfigFilePath = "/etc/nginx/nginx.conf"
)

type webRoot struct {
	Directive string
	Path      string
}

func Web(ctx context.Context, r runner.Runner) []model.Finding {
	services := []struct{ binary, name string }{{"nginx", "Nginx"}, {"caddy", "Caddy"}, {"apache2", "Apache HTTP Server"}, {"httpd", "Apache HTTP Server"}}
	var found []model.Finding
	seen := map[string]bool{}
	for _, s := range services {
		if _, err := r.LookPath(s.binary); err != nil {
			continue
		}
		if seen[s.name] {
			continue
		}
		seen[s.name] = true
		found = append(found, model.Finding{ID: "WEB-001", Status: model.INFO, Title: s.name + " detected", Explanation: "The server executable is available. This check does not verify whether it is configured as a reverse proxy or whether it is running."})
	}
	if len(found) == 0 {
		found = append(found, model.Finding{ID: "WEB-001", Status: model.INFO, Title: "No common reverse proxy detected", Explanation: "Nginx, Caddy, and Apache executables were not found. A reverse proxy is optional and this is not itself a problem."})
	}
	if _, ok := seen["Nginx"]; ok {
		found = append(found, checkNginxWebRoots(ctx, r)...)
	} else {
		found = append(found, model.Finding{ID: "WEB-002", Status: model.INFO, Title: "Nginx web roots could not be checked", Explanation: "Nginx is not installed or its executable was not found; no Nginx configuration was read."})
	}
	return found
}

func checkNginxWebRoots(ctx context.Context, r runner.Runner) []model.Finding {
	config, configNotes, err := loadNginxConfig(ctx, r)
	if err != nil {
		return []model.Finding{{ID: "WEB-002", Status: model.INFO, Title: "Nginx web roots could not be checked", Explanation: err.Error()}}
	}
	roots, variables := parseNginxRoots(config)
	var findings []model.Finding
	if len(configNotes) > 0 {
		findings = append(findings, model.Finding{ID: "WEB-002", Status: model.INFO, Title: "Some Nginx configuration files could not be read", Evidence: strings.Join(configNotes, "\n"), Explanation: "The web-root scan may be incomplete because not all included Nginx configuration files were readable."})
	}
	if len(variables) > 0 {
		findings = append(findings, model.Finding{ID: "WEB-002", Status: model.INFO, Title: "Some Nginx web roots contain variables", Evidence: strings.Join(variables, "\n"), Explanation: "Paths containing Nginx variables were not resolved or scanned."})
	}
	if len(roots) == 0 {
		if len(findings) == 0 {
			findings = append(findings, model.Finding{ID: "WEB-002", Status: model.INFO, Title: "No Nginx root or alias directives found", Explanation: "The available Nginx configuration did not contain a static root or alias path to scan."})
		}
		return findings
	}
	var hits []sensitiveFile
	var scanNotes []string
	visitedRoots := map[string]bool{}
	for _, root := range roots {
		if !path.IsAbs(root.Path) {
			scanNotes = append(scanNotes, fmt.Sprintf("%s %s: relative paths were not resolved against the Nginx prefix", root.Directive, root.Path))
			continue
		}
		clean := filepath.Clean(root.Path)
		if visitedRoots[clean] {
			continue
		}
		visitedRoots[clean] = true
		items, note := scanWebRoot(ctx, clean, maxWebRootDepth, maxWebRootFiles)
		hits = append(hits, items...)
		if note != "" {
			scanNotes = append(scanNotes, fmt.Sprintf("%s %s: %s", root.Directive, clean, note))
		}
	}
	if len(hits) == 0 {
		if len(scanNotes) > 0 {
			findings = append(findings, model.Finding{ID: "WEB-002", Status: model.INFO, Title: "Some Nginx web roots were not fully scanned", Evidence: strings.Join(scanNotes, "\n"), Explanation: "The scan is read-only, does not follow symbolic links, and is limited to depth 8 and 10000 files per root."})
		} else {
			findings = append(findings, model.Finding{ID: "WEB-002", Status: model.PASS, Title: "No sensitive files found under Nginx web roots", Explanation: "The configured static root and alias directories were scanned without reading file contents."})
		}
		return findings
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Path < hits[j].Path })
	for _, status := range []model.Status{model.HIGH, model.WARN} {
		var lines []string
		for _, hit := range hits {
			if hit.Status == status {
				lines = append(lines, hit.Evidence)
			}
		}
		if len(lines) == 0 {
			continue
		}
		title := "Backup or source map files found under Nginx web roots"
		if status == model.HIGH {
			title = "Sensitive files found under Nginx web roots"
		}
		findings = append(findings, model.Finding{ID: "WEB-002", Status: status, Title: title, Evidence: strings.Join(lines, "\n"), Explanation: "A file's presence does not prove that Nginx serves it. A deny rule may prevent delivery, but this check does not evaluate Nginx access rules."})
	}
	if len(scanNotes) > 0 {
		findings = append(findings, model.Finding{ID: "WEB-002", Status: model.INFO, Title: "Some Nginx web roots were not fully scanned", Evidence: strings.Join(scanNotes, "\n"), Explanation: "The scan is read-only, does not follow symbolic links, and is limited to depth 8 and 10000 files per root."})
	}
	return findings
}

func loadNginxConfig(ctx context.Context, r runner.Runner) (string, []string, error) {
	if _, err := r.LookPath("nginx"); err != nil {
		return "", nil, fmt.Errorf("nginx executable is unavailable")
	}
	if output, _, err := r.Run(ctx, "nginx", "-T"); err == nil && strings.TrimSpace(output) != "" {
		return output, nil, nil
	}
	var sections []string
	visited := map[string]bool{}
	var readConfig func(string, int)
	var readProblem string
	readConfig = func(path string, depth int) {
		if depth > maxWebRootDepth || visited[path] {
			return
		}
		visited[path] = true
		data, err := r.ReadFile(path)
		if err != nil {
			if path == nginxConfigFilePath || readProblem == "" {
				readProblem = err.Error()
			}
			return
		}
		text := string(data)
		sections = append(sections, text)
		for _, include := range parseNginxIncludes(text) {
			matches, err := filepath.Glob(include)
			if err != nil {
				readProblem = err.Error()
				continue
			}
			for _, match := range matches {
				readConfig(match, depth+1)
			}
		}
	}
	readConfig(nginxConfigFilePath, 0)
	if len(sections) == 0 {
		if readProblem == "" {
			readProblem = "no readable Nginx configuration was found"
		}
		return "", nil, fmt.Errorf("nginx -T was unavailable and the fallback configuration could not be read: %s", readProblem)
	}
	var notes []string
	if readProblem != "" {
		notes = append(notes, readProblem)
	}
	return strings.Join(sections, "\n"), notes, nil
}

func parseNginxIncludes(config string) []string {
	var includes []string
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		line := stripNginxComment(scanner.Text())
		match := nginxInclude.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		include := strings.Trim(strings.TrimSpace(match[1]), "\"'")
		if include != "" && !nginxVariable.MatchString(include) {
			includes = append(includes, include)
		}
	}
	return includes
}

func parseNginxRoots(config string) ([]webRoot, []string) {
	var roots []webRoot
	var variables []string
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		line := stripNginxComment(scanner.Text())
		for _, match := range webRootDirective.FindAllStringSubmatch(line, -1) {
			path := strings.Trim(strings.TrimSpace(match[3]), "\"'")
			if nginxVariable.MatchString(path) {
				variables = append(variables, fmt.Sprintf("%s %s (unresolved)", match[2], path))
				continue
			}
			if path != "" {
				roots = append(roots, webRoot{Directive: match[2], Path: path})
			}
		}
	}
	return roots, variables
}

func stripNginxComment(line string) string {
	var quote rune
	escaped := false
	for i, ch := range line {
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			continue
		}
		if ch == '#' {
			return line[:i]
		}
	}
	return line
}

type sensitiveFile struct {
	Path     string
	Status   model.Status
	Evidence string
}

func scanWebRoot(ctx context.Context, root string, maxDepth, maxFiles int) ([]sensitiveFile, string) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err.Error()
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, "root is a symbolic link and was not followed"
	}
	if !info.IsDir() {
		return nil, "root is not a directory"
	}
	var hits []sensitiveFile
	visited := 0
	limited := false
	var walkProblems []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if walkErr != nil {
			walkProblems = append(walkProblems, fmt.Sprintf("%s: %s", path, walkErr))
			return nil
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		depth := len(strings.Split(filepath.Clean(rel), string(filepath.Separator)))
		if entry.IsDir() && depth > maxDepth {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				hits = append(hits, sensitiveFile{Path: path, Status: model.HIGH, Evidence: fmt.Sprintf("Path: %s (directory); size: not measured", path)})
				return filepath.SkipDir
			}
			return nil
		}
		visited++
		if visited > maxFiles {
			limited = true
			return filepath.SkipAll
		}
		status, ok := classifySensitivePath(entry.Name())
		if !ok {
			return nil
		}
		fileInfo, statErr := entry.Info()
		if statErr != nil {
			walkProblems = append(walkProblems, fmt.Sprintf("%s: %s", path, statErr))
			return nil
		}
		hits = append(hits, sensitiveFile{Path: path, Status: status, Evidence: fmt.Sprintf("Path: %s; size: %d bytes", path, fileInfo.Size())})
		return nil
	})
	if err != nil && ctx.Err() != nil {
		return hits, "scan canceled"
	}
	if err != nil {
		return hits, err.Error()
	}
	if limited {
		walkProblems = append(walkProblems, fmt.Sprintf("file limit reached (%d)", maxFiles))
	}
	return hits, strings.Join(walkProblems, "; ")
}

func classifySensitivePath(name string) (model.Status, bool) {
	lower := strings.ToLower(name)
	if lower == ".env" || strings.HasPrefix(lower, ".env.") || strings.HasSuffix(lower, ".sql") || strings.HasSuffix(lower, ".sql.gz") || strings.HasSuffix(lower, ".dump") {
		return model.HIGH, true
	}
	for _, suffix := range []string{".bak", ".old", ".orig", "~", ".swp", ".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".map"} {
		if strings.HasSuffix(lower, suffix) {
			return model.WARN, true
		}
	}
	return "", false
}
