package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	_ "unsafe"

	// Linked for dockerCertDir below; the module's tags keep gpgme and the storage drivers out of the build.
	_ "go.podman.io/image/v5/docker"
	"go.podman.io/image/v5/docker/reference"
	dockerconfig "go.podman.io/image/v5/pkg/docker/config"
	"go.podman.io/image/v5/pkg/sysregistriesv2"
	"go.podman.io/image/v5/pkg/tlsclientconfig"
	"go.podman.io/image/v5/types"
)

// dockerCertDir is docker_client.go:150 of go.podman.io/image v5.40.0: where the per-host certificates of a registry
// are, which no exported function returns.
//
//go:linkname dockerCertDir go.podman.io/image/v5/docker.dockerCertDir
func dockerCertDir(sys *types.SystemContext, hostPort string) (string, error)

// CrioEnv is what go.podman.io/image reads from the process and from CRI-O's settings, for one case. Paths are
// relative to the case's root; a nil pointer is a variable that is not set.
type CrioEnv struct {
	Root                      string            `json:"root"`
	Files                     map[string]string `json:"files"`
	UID                       int               `json:"uid"`
	Home                      string            `json:"home"`
	XDGConfigHome             *string           `json:"xdg_config_home"`
	XDGRuntimeDir             *string           `json:"xdg_runtime_dir"`
	DockerConfig              *string           `json:"docker_config"`
	EnvRegistriesConf         *string           `json:"env_registries_conf"`
	EnvRegistriesConfOverride *string           `json:"env_registries_conf_override"`
	RegistriesConf            *string           `json:"registries_conf"`
	RegistriesConfDir         *string           `json:"registries_conf_dir"`
	AuthFile                  *string           `json:"auth_file"`
}

// apply lays out the files, sets the environment the library reads and returns the system context, and the function
// that restores the environment.
func (e CrioEnv) apply() (*types.SystemContext, func(), error) {
	if err := materialise(e.Root, e.Files); err != nil {
		return nil, nil, err
	}
	abs := func(p *string) string {
		if p == nil {
			return ""
		}
		return filepath.Join(e.Root, *p)
	}
	restore := setEnv(map[string]*string{
		"HOME":                                ptr(filepath.Join(e.Root, e.Home)),
		"XDG_CONFIG_HOME":                     ptrIf(e.XDGConfigHome, abs),
		"XDG_RUNTIME_DIR":                     ptrIf(e.XDGRuntimeDir, abs),
		"DOCKER_CONFIG":                       ptrIf(e.DockerConfig, abs),
		"CONTAINERS_REGISTRIES_CONF":          ptrIf(e.EnvRegistriesConf, abs),
		"CONTAINERS_REGISTRIES_CONF_OVERRIDE": ptrIf(e.EnvRegistriesConfOverride, abs),
		"_CONTAINERS_ROOTLESS_UID":            ptr(strconv.Itoa(e.UID)),
	})
	sys := &types.SystemContext{
		RootForImplicitAbsolutePaths: e.Root,
		SystemRegistriesConfPath:     abs(e.RegistriesConf),
		SystemRegistriesConfDirPath:  abs(e.RegistriesConfDir),
		AuthFilePath:                 abs(e.AuthFile),
	}
	sysregistriesv2.InvalidateCache()
	return sys, restore, nil
}

func ptr(s string) *string { return &s }

// ptrIf is the path of p made absolute, or nil when p is nil.
func ptrIf(p *string, abs func(*string) string) *string {
	if p == nil {
		return nil
	}
	return ptr(abs(p))
}

// setEnv sets each variable, or unsets it for nil, and returns what restores them.
func setEnv(vars map[string]*string) func() {
	type previous struct {
		value string
		set   bool
	}
	saved := map[string]previous{}
	for name, value := range vars {
		old, set := os.LookupEnv(name)
		saved[name] = previous{old, set}
		if value == nil {
			os.Unsetenv(name)
		} else {
			os.Setenv(name, *value)
		}
	}
	return func() {
		for name, p := range saved {
			if p.set {
				os.Setenv(name, p.value)
			} else {
				os.Unsetenv(name)
			}
		}
	}
}

// RegistriesCase is one `registries` case: the files, and the references to resolve.
type RegistriesCase struct {
	CrioEnv
	References []string `json:"references"`
}

// Endpoint is a sysregistriesv2.Endpoint as JSON.
type Endpoint struct {
	Location       string `json:"location"`
	Insecure       bool   `json:"insecure"`
	PullFromMirror string `json:"pull_from_mirror"`
}

// RegistryAnswer is a sysregistriesv2.Registry as JSON.
type RegistryAnswer struct {
	Prefix             string     `json:"prefix"`
	Location           string     `json:"location"`
	Insecure           bool       `json:"insecure"`
	Blocked            bool       `json:"blocked"`
	MirrorByDigestOnly bool       `json:"mirror_by_digest_only"`
	Mirrors            []Endpoint `json:"mirrors"`
}

// Source is a sysregistriesv2.PullSource as JSON.
type Source struct {
	Endpoint
	Reference string `json:"reference"`
}

// Resolution is what a reference resolves to: the prefix of its registry, empty when none, and its pull sources.
type Resolution struct {
	Reference string   `json:"reference"`
	Prefix    string   `json:"prefix"`
	Sources   []Source `json:"sources"`
	Error     string   `json:"error,omitempty"`
}

// RegistriesAnswer is the answer to a RegistriesCase: the merged registries, the credential helpers, and each
// reference; or Error.
type RegistriesAnswer struct {
	Error             string           `json:"error,omitempty"`
	Registries        []RegistryAnswer `json:"registries"`
	CredentialHelpers []string         `json:"credential_helpers"`
	Resolutions       []Resolution     `json:"resolutions"`
}

func registriesCase(line []byte) (any, error) {
	var c RegistriesCase
	if err := json.Unmarshal(line, &c); err != nil {
		return nil, err
	}
	sys, restore, err := c.apply()
	if err != nil {
		return nil, err
	}
	defer restore()
	answer := RegistriesAnswer{Registries: []RegistryAnswer{}, CredentialHelpers: []string{}, Resolutions: []Resolution{}}
	conf, err := sysregistriesv2.TryUpdatingCache(sys)
	if err != nil {
		answer.Error = err.Error()
		return answer, nil
	}
	for _, r := range conf.Registries {
		answer.Registries = append(answer.Registries, RegistryAnswer{
			Prefix: r.Prefix, Location: r.Location, Insecure: r.Insecure, Blocked: r.Blocked,
			MirrorByDigestOnly: r.MirrorByDigestOnly, Mirrors: endpoints(r.Mirrors),
		})
	}
	answer.CredentialHelpers = conf.CredentialHelpers
	for _, text := range c.References {
		answer.Resolutions = append(answer.Resolutions, resolve(sys, text))
	}
	return answer, nil
}

func endpoints(list []sysregistriesv2.Endpoint) []Endpoint {
	out := []Endpoint{}
	for _, e := range list {
		out = append(out, Endpoint{Location: e.Location, Insecure: e.Insecure, PullFromMirror: e.PullFromMirror})
	}
	return out
}

// resolve does what docker_image_src.go:56 does for an image: finds the registry by the name, then its sources.
func resolve(sys *types.SystemContext, text string) Resolution {
	out := Resolution{Reference: text, Sources: []Source{}}
	named, err := reference.ParseNormalizedNamed(text)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Reference = named.String()
	registry, err := sysregistriesv2.FindRegistry(sys, named.Name())
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if registry == nil {
		return out
	}
	out.Prefix = registry.Prefix
	sources, err := registry.PullSourcesFromReference(named)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	for _, s := range sources {
		out.Sources = append(out.Sources, Source{
			Endpoint:  Endpoint{Location: s.Endpoint.Location, Insecure: s.Endpoint.Insecure, PullFromMirror: s.Endpoint.PullFromMirror},
			Reference: s.Reference.String(),
		})
	}
	return out
}

// CertsCase is one `certs` case: the files, and the host and port to look up.
type CertsCase struct {
	CrioEnv
	HostPort string `json:"host_port"`
}

// CertsAnswer is the answer to a CertsCase: the directory found (empty when none), and what it holds.
type CertsAnswer struct {
	Dir     string `json:"dir"`
	Error   string `json:"error,omitempty"`
	Clients int    `json:"clients"`
}

func certsCase(line []byte) (any, error) {
	var c CertsCase
	if err := json.Unmarshal(line, &c); err != nil {
		return nil, err
	}
	sys, restore, err := c.apply()
	if err != nil {
		return nil, err
	}
	defer restore()
	var answer CertsAnswer
	dir, err := dockerCertDir(sys, c.HostPort)
	if err != nil {
		answer.Error = err.Error()
		return answer, nil
	}
	answer.Dir = strings.TrimPrefix(dir, c.Root)
	if dir == "" {
		return answer, nil
	}
	config := &tls.Config{}
	if err := tlsclientconfig.SetupCertificates(dir, config); err != nil {
		answer.Error = err.Error()
		return answer, nil
	}
	answer.Clients = len(config.Certificates)
	return answer, nil
}

// AuthCase is one `auth` case: the files, and the keys to look up.
type AuthCase struct {
	CrioEnv
	Keys []string `json:"keys"`
}

// Login is a types.DockerAuthConfig as JSON.
type Login struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identity_token"`
}

// AuthResult is the login of a key, nil when there is none, or the error.
type AuthResult struct {
	Key   string `json:"key"`
	Login *Login `json:"login"`
	Error string `json:"error,omitempty"`
}

func authCase(line []byte) (any, error) {
	var c AuthCase
	if err := json.Unmarshal(line, &c); err != nil {
		return nil, err
	}
	sys, restore, err := c.apply()
	if err != nil {
		return nil, err
	}
	defer restore()
	// An auth file with two entries for one registry is searched in map order, and a small map starts
	// at a random one of eight slots: ask again and again, and say so when the answers differ.
	var first []byte
	for range 64 {
		answer := []AuthResult{}
		for _, key := range c.Keys {
			result := AuthResult{Key: key}
			creds, err := dockerconfig.GetCredentials(sys, key)
			switch {
			case err != nil:
				result.Error = err.Error()
			case creds != (types.DockerAuthConfig{}):
				result.Login = &Login{creds.Username, creds.Password, creds.IdentityToken}
			}
			answer = append(answer, result)
		}
		encoded, err := json.Marshal(answer)
		if err != nil {
			return nil, err
		}
		if first == nil {
			first = encoded
		} else if !bytes.Equal(first, encoded) {
			return map[string]bool{"unstable": true}, nil
		}
	}
	return json.RawMessage(first), nil
}
