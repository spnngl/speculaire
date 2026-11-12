// Command speculaire-oracle runs containerd's and NRI's own code on the cases the Rust ports also run, so that tests
// can compare both answers (D29). It is a test tool: no release artifact, package or image contains it.
//
// `version` reads nothing and prints the containerd and NRI versions the oracle links. Every other subcommand reads
// cases as JSON lines on stdin and prints one JSON line per case on stdout (D70): `hosts` and `config` run containerd's
// registry configuration code, `registries`, `certs` and `auth` that of go.podman.io/image, which CRI-O links.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	// The plugins the daemon registers: `config` runs their configuration migrations, in the daemon's order.
	_ "github.com/containerd/containerd/v2/cmd/containerd/builtins"
	// Linked so that the build info records the NRI version; the subcommands of M6 call into it.
	_ "github.com/containerd/nri/pkg/api"
)

const (
	containerdModule = "github.com/containerd/containerd/v2"
	nriModule        = "github.com/containerd/nri"
)

// maxCase is the longest JSON line a subcommand reads.
const maxCase = 16 << 20

// Versions are the module versions the oracle links, as `go.mod` pins them.
type Versions struct {
	Containerd string `json:"containerd"`
	NRI        string `json:"nri"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// subcommands maps a name to the function that answers one case.
var subcommands = map[string]func(line []byte) (any, error){
	"hosts":      hostsCase,
	"config":     configCase,
	"registries": registriesCase,
	"certs":      certsCase,
	"auth":       authCase,
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		return usage(stderr)
	}
	if args[0] == "version" {
		return printVersions(stdout, stderr)
	}
	answer, ok := subcommands[args[0]]
	if !ok {
		return usage(stderr)
	}
	return answerLines(answer, stdin, stdout, stderr)
}

func usage(stderr io.Writer) int {
	fmt.Fprintln(stderr, "usage: speculaire-oracle version | hosts | config | registries | certs | auth")
	return 2
}

// answerLines prints one line per case: the answer, or `{"oracle_error":"..."}` when the case is not valid input.
// A panic of containerd's code is the case's answer, `{"error":"panic: ..."}`: a daemon would have crashed on it,
// which is an error as far as a config is concerned.
func answerLines(answer func([]byte) (any, error), stdin io.Reader, stdout, stderr io.Writer) int {
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 0, 1<<20), maxCase)
	encoder := json.NewEncoder(stdout)
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		result, err := safely(answer, scanner.Bytes())
		if err != nil {
			result = map[string]string{"oracle_error": err.Error()}
		}
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintf(stderr, "speculaire-oracle: %v\n", err)
			return 1
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(stderr, "speculaire-oracle: %v\n", err)
		return 1
	}
	return 0
}

func safely(answer func([]byte) (any, error), line []byte) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			result, err = map[string]string{"error": fmt.Sprintf("panic: %v", r)}, nil
		}
	}()
	return answer(line)
}

func printVersions(stdout, stderr io.Writer) int {
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
