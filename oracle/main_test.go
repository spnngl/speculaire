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
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
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

func TestUsageExitsTwo(t *testing.T) {
	for _, args := range [][]string{nil, {"versions"}, {"version", "extra"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Errorf("%q: exit %d, stdout %q", args, code, stdout.String())
		}
	}
}
