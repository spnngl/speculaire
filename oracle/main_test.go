package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// goList returns the version `go list` selects for a module of the build.
func goList(t *testing.T, module string) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}", module).Output()
	if err != nil {
		t.Fatalf("go list -m %s: %v", module, err)
	}
	return strings.TrimSpace(string(out))
}

func TestVersionPrintsTheSelectedModules(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var got Versions
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("%q: %v", stdout.String(), err)
	}
	want := Versions{Containerd: goList(t, containerdModule), NRI: goList(t, nriModule)}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// The NRI pin moves only with containerd (D29): the selected NRI is the one the containerd release requires.
func TestNRIIsTheVersionContainerdRequires(t *testing.T) {
	out, err := exec.Command("go", "mod", "graph").Output()
	if err != nil {
		t.Fatalf("go mod graph: %v", err)
	}
	parent := containerdModule + "@" + goList(t, containerdModule)
	required := ""
	for _, line := range strings.Split(string(out), "\n") {
		from, to, ok := strings.Cut(line, " ")
		if ok && from == parent && strings.HasPrefix(to, nriModule+"@") {
			required = strings.TrimPrefix(to, nriModule+"@")
		}
	}
	if selected := goList(t, nriModule); required != selected {
		t.Fatalf("%s requires NRI %q, go.mod selects %q", parent, required, selected)
	}
}

// Only a version 1 file whose sections the migration renames to one name merges them in map order.
func TestSectionsMergeOnlyWhenTheMigrationRenamesTwoToOne(t *testing.T) {
	for text, want := range map[string]bool{
		"[plugins.cri.registry]\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n":                true,
		"version = 1\n[plugins.cri]\n[plugins.\"io.containerd.grpc.v1.cri\"]\n":                     true,
		"version = 2\n[plugins.cri]\n[plugins.\"io.containerd.grpc.v1.cri\"]\n":                     false,
		"version = 1\n[plugins.cri.registry]\n[plugins.\"io.containerd.cri.v1.images\".registry]\n": false,
		"version = 1\n[plugins.cri\n": false,
	} {
		if got := sectionsMerge(map[string]string{"config.toml": text}); got != want {
			t.Errorf("%q: got %v, want %v", text, got, want)
		}
	}
}

func TestUsageExitsTwo(t *testing.T) {
	for _, args := range [][]string{nil, {"versions"}, {"version", "extra"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Errorf("%q: exit %d, stdout %q", args, code, stdout.String())
		}
	}
}
