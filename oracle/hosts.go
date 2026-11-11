package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/remotes/docker/config"
)

// hostConfig mirrors the unexported type of core/remotes/docker/config at v2.4.2 (hosts.go:45), field for field: the
// linknamed functions below return it. A containerd release that changes it makes the `hosts` tests fail, or crash:
// that is the signal to port the change.
type hostConfig struct {
	scheme string
	host   string
	path   string

	capabilities docker.HostCapabilities

	caCerts     []string
	clientPairs [][2]string
	skipVerify  *bool

	dialTimeout *time.Duration

	header http.Header
}

// parseHostsFile is hosts.go:380: the `hosts.toml` parser, which no exported function reaches without the fallback to
// certificate files.
//
//go:linkname parseHostsFile github.com/containerd/containerd/v2/core/remotes/docker/config.parseHostsFile
func parseHostsFile(baseDir string, b []byte) ([]hostConfig, error)

// loadHostDir is hosts.go:315: `hosts.toml`, or the certificate files of Docker's layout.
//
//go:linkname loadHostDir github.com/containerd/containerd/v2/core/remotes/docker/config.loadHostDir
func loadHostDir(ctx context.Context, hostsDir string) ([]hostConfig, error)

// HostsCase is one `hosts` case: files laid out under Root (a `certs.d`), and the registry host to resolve.
type HostsCase struct {
	Root          string            `json:"root"`
	Files         map[string]string `json:"files"`
	Host          string            `json:"host"`
	DefaultScheme string            `json:"default_scheme"`
}

// Parsed is a hostConfig as JSON.
type Parsed struct {
	Scheme       string              `json:"scheme"`
	Host         string              `json:"host"`
	Path         string              `json:"path"`
	Capabilities []string            `json:"capabilities"`
	CA           []string            `json:"ca"`
	Client       [][2]string         `json:"client"`
	SkipVerify   *bool               `json:"skip_verify"`
	DialTimeout  *int64              `json:"dial_timeout_ns"`
	Header       map[string][]string `json:"header"`
}

// Resolved is a docker.RegistryHost as JSON.
type Resolved struct {
	Scheme       string              `json:"scheme"`
	Host         string              `json:"host"`
	Path         string              `json:"path"`
	Capabilities []string            `json:"capabilities"`
	Header       map[string][]string `json:"header"`
	Fallback     bool                `json:"fallback"`
	SkipVerify   bool                `json:"skip_verify"`
}

// Outcome is a list, or the error that replaced it.
type Outcome[T any] struct {
	Ok    []T    `json:"ok"`
	Error string `json:"error,omitempty"`
}

// HostsAnswer is the answer to a HostsCase. Dir is the directory `HostDirFromRoot` found, empty when none exists;
// Parsed is present when it holds a `hosts.toml`.
type HostsAnswer struct {
	Dir      string             `json:"dir"`
	Parsed   *Outcome[Parsed]   `json:"parsed"`
	Loaded   *Outcome[Parsed]   `json:"loaded"`
	Resolved *Outcome[Resolved] `json:"resolved"`
}

func hostsCase(line []byte) (any, error) {
	var c HostsCase
	if err := json.Unmarshal(line, &c); err != nil {
		return nil, err
	}
	if err := materialise(c.Root, c.Files); err != nil {
		return nil, err
	}
	ctx := context.Background()
	answer := HostsAnswer{}
	if dir, err := config.HostDirFromRoot(c.Root)(c.Host); err == nil {
		answer.Dir = dir
		if text, readErr := os.ReadFile(filepath.Join(dir, "hosts.toml")); readErr == nil && len(text) > 0 {
			answer.Parsed = parsed(parseHostsFile(dir, text))
		}
		answer.Loaded = parsed(loadHostDir(ctx, dir))
	}
	hosts, err := config.ConfigureHosts(ctx, config.HostOptions{
		HostDir:       config.HostDirFromRoot(c.Root),
		DefaultScheme: c.DefaultScheme,
	})(c.Host)
	answer.Resolved = &Outcome[Resolved]{Ok: []Resolved{}}
	if err != nil {
		answer.Resolved.Error = err.Error()
	}
	for _, h := range hosts {
		answer.Resolved.Ok = append(answer.Resolved.Ok, resolved(h))
	}
	return answer, nil
}

func parsed(hosts []hostConfig, err error) *Outcome[Parsed] {
	if err != nil {
		return &Outcome[Parsed]{Ok: []Parsed{}, Error: err.Error()}
	}
	out := &Outcome[Parsed]{Ok: []Parsed{}}
	for _, h := range hosts {
		p := Parsed{
			Scheme: h.scheme, Host: h.host, Path: h.path, Capabilities: capabilities(h.capabilities),
			CA: orEmpty(h.caCerts), Client: h.clientPairs, SkipVerify: h.skipVerify, Header: headers(h.header),
		}
		if p.Client == nil {
			p.Client = [][2]string{}
		}
		if h.dialTimeout != nil {
			ns := h.dialTimeout.Nanoseconds()
			p.DialTimeout = &ns
		}
		out.Ok = append(out.Ok, p)
	}
	return out
}

func resolved(h docker.RegistryHost) Resolved {
	r := Resolved{
		Scheme: h.Scheme, Host: h.Host, Path: h.Path, Capabilities: capabilities(h.Capabilities), Header: headers(h.Header),
	}
	transport := h.Client.Transport
	if strings.HasSuffix(fmt.Sprintf("%T", transport), ".httpFallback") {
		r.Fallback = true
		// The wrapped transport is its first field, `super`.
		field := reflect.ValueOf(transport).Elem().Field(0)
		if inner, ok := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(http.RoundTripper); ok {
			transport = inner
		}
	}
	if t, ok := transport.(*http.Transport); ok && t.TLSClientConfig != nil {
		r.SkipVerify = t.TLSClientConfig.InsecureSkipVerify
	}
	return r
}

func capabilities(c docker.HostCapabilities) []string {
	names := []string{}
	for _, named := range []struct {
		bit  docker.HostCapabilities
		name string
	}{
		{docker.HostCapabilityPull, "pull"},
		{docker.HostCapabilityResolve, "resolve"},
		{docker.HostCapabilityPush, "push"},
		{docker.HostCapabilityReferrers, "referrers"},
	} {
		if c.Has(named.bit) {
			names = append(names, named.name)
		}
	}
	return names
}

func headers(h http.Header) map[string][]string {
	out := map[string][]string{}
	for k, v := range h {
		out[k] = slices.Clone(v)
	}
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
