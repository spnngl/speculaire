// Command speculaire-oracle runs containerd's and NRI's own code on the cases the Rust ports also run, so that tests
// can compare both answers (D29). It is a test tool: no release artifact, package or image contains it.
//
// Each subcommand reads cases as JSON lines on stdin and prints one JSON line per case on stdout. `version` reads
// nothing and prints the containerd and NRI versions the oracle links.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	// Linked so that the build info records their versions; the subcommands of M2 and M6 call into both.
	_ "github.com/containerd/containerd/v2/version"
	_ "github.com/containerd/nri/pkg/api"
)

const (
	containerdModule = "github.com/containerd/containerd/v2"
	nriModule        = "github.com/containerd/nri"
)

// Versions are the module versions the oracle links, as `go.mod` pins them.
type Versions struct {
	Containerd string `json:"containerd"`
	NRI        string `json:"nri"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "version" {
		fmt.Fprintln(stderr, "usage: speculaire-oracle version")
		return 2
	}
	versions, err := linked()
	if err != nil {
		fmt.Fprintf(stderr, "speculaire-oracle: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(versions); err != nil {
		fmt.Fprintf(stderr, "speculaire-oracle: %v\n", err)
		return 1
	}
	return 0
}

// linked reads the containerd and NRI versions from the binary's build info.
func linked() (Versions, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Versions{}, errors.New("the binary has no build info")
	}
	var versions Versions
	for _, dep := range info.Deps {
		switch dep.Path {
		case containerdModule:
			versions.Containerd = dep.Version
		case nriModule:
			versions.NRI = dep.Version
		}
	}
	if versions.Containerd == "" || versions.NRI == "" {
		return Versions{}, fmt.Errorf("the build info lacks %s or %s: %+v", containerdModule, nriModule, versions)
	}
	return versions, nil
}
