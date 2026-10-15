package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vps-check/internal/model"
)

func TestParseNginxRoots(t *testing.T) {
	config := `
# root /ignored/comment;
http {
  server {
    root /srv/www/site; # inline comment
    location /assets/ { alias "/srv/assets"; }
    location /user/ { alias $hosted_root; }
    root /srv/${tenant};
  }
}
`
	roots, variables := parseNginxRoots(config)
	if len(roots) != 2 || roots[0] != (webRoot{Directive: "root", Path: "/srv/www/site"}) || roots[1] != (webRoot{Directive: "alias", Path: "/srv/assets"}) {
		t.Fatalf("unexpected roots: %+v", roots)
	}
	if len(variables) != 2 || !strings.Contains(strings.Join(variables, "\n"), "$hosted_root") || !strings.Contains(strings.Join(variables, "\n"), "${tenant}") {
		t.Fatalf("variable paths were not reported: %v", variables)
	}
}

func TestParseNginxIncludes(t *testing.T) {
	got := parseNginxIncludes("# include /ignored;\ninclude /etc/nginx/sites-enabled/*;\ninclude '$custom';\ninclude /etc/nginx/conf.d/*.conf;\n")
	if len(got) != 2 || got[0] != "/etc/nginx/sites-enabled/*" || got[1] != "/etc/nginx/conf.d/*.conf" {
		t.Fatalf("unexpected includes: %v", got)
	}
}

func TestLoadNginxConfigFallsBackToIncludedFiles(t *testing.T) {
	root := t.TempDir()
	includeDir := filepath.Join(root, "sites-enabled")
	if err := os.Mkdir(includeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mainConfig := filepath.Join(root, "nginx.conf")
	childConfig := filepath.Join(includeDir, "site.conf")
	if err := os.WriteFile(mainConfig, []byte("include "+filepath.Join(includeDir, "*.conf")+";\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(childConfig, []byte("root /srv/example;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := fakeRunner{
		paths:  map[string]bool{"nginx": true},
		errors: map[string]error{"nginx -T": errors.New("permission denied")},
		files:  map[string][]byte{mainConfig: []byte("include " + filepath.Join(includeDir, "*.conf") + ";\n"), childConfig: []byte("root /srv/example;\n")},
	}
	old := nginxConfigFilePath
	nginxConfigFilePath = mainConfig
	t.Cleanup(func() { nginxConfigFilePath = old })
	config, notes, err := loadNginxConfig(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Fatalf("unexpected fallback notes: %v", notes)
	}
	if !strings.Contains(config, "root /srv/example;") {
		t.Fatalf("included config was not read: %q", config)
	}
}

func TestScanWebRootFindingsAndDoesNotReadContents(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		".env":          "secret-content-must-not-appear",
		".env.local":    "local-secret",
		"db.sql.gz":     "database-content",
		"backup.tar.gz": "archive-content",
		"app.js.map":    "source-map-content",
		"normal.txt":    "ordinary-content",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "package.sql"), []byte("still detect this"), 0o600); err != nil {
		t.Fatal(err)
	}
	hits, note := scanWebRoot(context.Background(), root, maxWebRootDepth, maxWebRootFiles)
	if note != "" {
		t.Fatalf("unexpected scan note: %s", note)
	}
	if len(hits) != 7 {
		t.Fatalf("got %d sensitive paths, want 7: %+v", len(hits), hits)
	}
	seen := map[string]model.Status{}
	var evidence strings.Builder
	for _, hit := range hits {
		seen[filepath.Base(hit.Path)] = hit.Status
		evidence.WriteString(hit.Evidence)
	}
	for name, want := range map[string]model.Status{".env": model.HIGH, ".env.local": model.HIGH, ".git": model.HIGH, "db.sql.gz": model.HIGH, "backup.tar.gz": model.WARN, "app.js.map": model.WARN, "package.sql": model.HIGH} {
		if got, ok := seen[name]; !ok || got != want {
			t.Errorf("%s status = %s (present %t), want %s", name, got, ok, want)
		}
	}
	for _, content := range files {
		if strings.Contains(evidence.String(), content) {
			t.Errorf("file content leaked into evidence: %q", content)
		}
	}
	if !strings.Contains(evidence.String(), "size:") || !strings.Contains(evidence.String(), root) {
		t.Fatalf("evidence does not include paths and file sizes: %q", evidence.String())
	}
}

func TestScanWebRootSkipsSymlinksAndHonorsLimits(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	secret := filepath.Join(target, ".env")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if got, note := scanWebRoot(context.Background(), root, 8, 100); note != "" || len(got) != 0 {
		t.Fatalf("symbolic link was followed: hits=%+v note=%q", got, note)
	}
	deep := filepath.Join(root, "one", "two")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "hidden.bak"), []byte("backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, note := scanWebRoot(context.Background(), root, 1, 100); note != "" || len(got) != 0 {
		t.Fatalf("depth limit was not honored: hits=%+v note=%q", got, note)
	}
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, note := scanWebRoot(context.Background(), root, 8, 1); !strings.Contains(note, "file limit reached") {
		t.Fatalf("file limit note = %q", note)
	}
}

func TestClassifySensitivePathPatterns(t *testing.T) {
	tests := []struct {
		name string
		want model.Status
	}{
		{".env", model.HIGH}, {".env.production", model.HIGH}, {"backup.sql", model.HIGH},
		{"backup.sql.gz", model.HIGH}, {"database.dump", model.HIGH},
		{"site.bak", model.WARN}, {"site.old", model.WARN}, {"site.orig", model.WARN},
		{"site~", model.WARN}, {"site.swp", model.WARN}, {"backup.zip", model.WARN},
		{"backup.tar", model.WARN}, {"backup.tar.gz", model.WARN}, {"backup.tgz", model.WARN},
		{"backup.7z", model.WARN}, {"app.js.map", model.WARN},
	}
	for _, test := range tests {
		got, ok := classifySensitivePath(test.name)
		if !ok || got != test.want {
			t.Errorf("classifySensitivePath(%q) = (%s, %t), want (%s, true)", test.name, got, ok, test.want)
		}
	}
	for _, name := range []string{"index.html", "notes.sql.txt", ".envrc", "node_modules"} {
		if _, ok := classifySensitivePath(name); ok {
			t.Errorf("classifySensitivePath(%q) unexpectedly matched", name)
		}
	}
}

func TestWeb002ReportsNginxUnavailable(t *testing.T) {
	got := Web(context.Background(), fakeRunner{})
	for _, finding := range got {
		if finding.ID == "WEB-002" {
			if finding.Status != model.INFO || !strings.Contains(finding.Explanation, "not installed") {
				t.Fatalf("unexpected WEB-002: %+v", finding)
			}
			return
		}
	}
	t.Fatal("WEB-002 finding was missing")
}
