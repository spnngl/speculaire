// Command check compares the failures of a conformance run with the ones that are expected (D85).
//
//	check console.txt expected-failures.txt
//
// The input is what the suite prints: its `Test results` tree, one test per line as `name: status`, a child more
// indented than its parent. (The suite's own junit.xml is not written at the pinned commit: its results.yaml step
// dereferences a nil pointer when push is off.) A failed test with no failed child is a failure of its own, named by
// the line. The expected file has one name per line, then ` # why`; blank lines and lines that start with `#` are
// comments. The command fails when a test fails that is not listed, when a listed test does not fail, and when no
// test passes: a list that is not exactly the failures is a list nobody reads.
package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

type line struct {
	indent int
	name   string
	status string
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: check console.txt expected-failures.txt")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "check:", err)
		os.Exit(1)
	}
}

func run(console, expected string) error {
	tree, err := results(console)
	if err != nil {
		return err
	}
	failed := map[string]bool{}
	passed := 0
	for i, l := range tree {
		leaf := i+1 == len(tree) || tree[i+1].indent <= l.indent
		switch {
		case l.status == "FAIL" && leaf:
			failed[l.name] = true
		case l.status == "Pass" && leaf:
			passed++
		}
	}
	want, err := listed(expected)
	if err != nil {
		return err
	}
	var problems []string
	for name := range failed {
		if !want[name] {
			problems = append(problems, "failed, and not expected to: "+name)
		}
	}
	for name := range want {
		if !failed[name] {
			problems = append(problems, "expected to fail, and did not: "+name)
		}
	}
	if passed == 0 {
		problems = append(problems, "no test passed: the suite did not run")
	}
	sort.Strings(problems)
	fmt.Printf("conformance: %d tests passed, %d failed that are expected to\n", passed, len(failed))
	if len(problems) > 0 {
		return fmt.Errorf("%d problems:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// results reads the tests of the `Test results` section: the lines up to the first blank one.
func results(path string) ([]line, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var tree []line
	inside := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		switch {
		case !inside:
			inside = text == "Test results"
		case strings.TrimSpace(text) == "":
			return tree, scanner.Err()
		case strings.HasPrefix(strings.TrimSpace(text), "- "):
			// The message of the failure above.
		default:
			trimmed := strings.TrimLeft(text, " ")
			name, status, ok := strings.Cut(trimmed, ": ")
			if !ok {
				return nil, fmt.Errorf("%s: not a result: %q", path, text)
			}
			tree = append(tree, line{indent: len(text) - len(trimmed), name: name, status: status})
		}
	}
	if len(tree) == 0 {
		return nil, fmt.Errorf("%s: no `Test results` in it", path)
	}
	return tree, scanner.Err()
}

func listed(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		name, _, _ := strings.Cut(text, " # ")
		names[strings.TrimSpace(name)] = true
	}
	return names, scanner.Err()
}
