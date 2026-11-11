package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"
	"github.com/sirupsen/logrus"

	srvconfig "github.com/containerd/containerd/v2/cmd/containerd/server/config"
	"github.com/containerd/containerd/v2/version"
)

// imagesPlugin is the CRI image service, whose configuration holds the registry section of a version 3 or 4 config.
const imagesPlugin = "io.containerd.cri.v1.images"

func init() {
	// The loader warns about every unknown key; cases are not the place to read that.
	logrus.SetOutput(io.Discard)
}

// ConfigCase is one `config` case: files laid out under Root, loaded from Entry as `containerd --config` does.
type ConfigCase struct {
	Root  string            `json:"root"`
	Files map[string]string `json:"files"`
	Entry string            `json:"entry"`
}

// Auth is the `auth` of a `configs."<host>"` table.
type Auth struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	Auth          string `json:"auth"`
	IdentityToken string `json:"identitytoken"`
}

// Registry is the registry section as the CRI image service decodes it, before it validates it.
type Registry struct {
	ConfigPath string              `json:"config_path"`
	Mirrors    map[string][]string `json:"mirrors"`
	Configs    map[string]*Auth    `json:"configs"`
	Auths      map[string]Auth     `json:"auths"`
	Headers    map[string][]string `json:"headers"`
}

// ConfigAnswer is the answer to a ConfigCase: the registry section, or the loader's refusal.
type ConfigAnswer struct {
	Registry *Registry `json:"registry,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// criRegistry is the part of the CRI image config the oracle reads, through its JSON tags: the type is internal to
// containerd.
type criRegistry struct {
	Registry struct {
		ConfigPath string `json:"configPath"`
		Mirrors    map[string]struct {
			Endpoint []string `json:"endpoint"`
		} `json:"mirrors"`
		Configs map[string]struct {
			Auth *Auth `json:"auth"`
		} `json:"configs"`
		Auths   map[string]Auth     `json:"auths"`
		Headers map[string][]string `json:"headers"`
	} `json:"registry"`
}

func configCase(line []byte) (any, error) {
	var c ConfigCase
	if err := json.Unmarshal(line, &c); err != nil {
		return nil, err
	}
	if err := materialise(c.Root, c.Files); err != nil {
		return nil, err
	}
	// containerd's v1 migration renames the plugins through a map, so two sections that get the same name merge in a
	// random order: a case whose answer changes between runs is unstable and no answer to compare with.
	path := filepath.Join(c.Root, c.Entry)
	first := loadRegistry(context.Background(), path)
	want, err := json.Marshal(first)
	if err != nil {
		return nil, err
	}
	for range 64 {
		got, err := json.Marshal(loadRegistry(context.Background(), path))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, want) {
			return map[string]bool{"unstable": true}, nil
		}
	}
	return first, nil
}

// loadRegistry does what `containerd --config path` does to the registry section: it loads the file and its imports
// with the daemon's plugin migrations, then decodes the CRI image service's config.
func loadRegistry(ctx context.Context, path string) ConfigAnswer {
	graph := registry.Graph(func(*plugin.Registration) bool { return false })
	plugins := func() iter.Seq[plugin.Registration] { return slices.Values(graph) }
	config := &srvconfig.Config{Version: version.ConfigVersion}
	if err := srvconfig.LoadConfigWithPlugins(ctx, path, plugins, config); err != nil {
		return ConfigAnswer{Error: err.Error()}
	}
	for _, p := range graph {
		if p.URI() != imagesPlugin {
			continue
		}
		// Registration.Config is shared by every case: decode into a copy of it.
		fresh := reflect.New(reflect.TypeOf(p.Config).Elem())
		fresh.Elem().Set(reflect.ValueOf(p.Config).Elem())
		if _, err := config.Decode(ctx, p.URI(), fresh.Interface()); err != nil {
			return ConfigAnswer{Error: err.Error()}
		}
		return ConfigAnswer{Registry: registryOf(fresh.Interface())}
	}
	return ConfigAnswer{Error: fmt.Sprintf("the daemon registers no %s plugin", imagesPlugin)}
}

func registryOf(imageConfig any) *Registry {
	raw, err := json.Marshal(imageConfig)
	if err != nil {
		panic(err)
	}
	var cri criRegistry
	if err := json.Unmarshal(raw, &cri); err != nil {
		panic(err)
	}
	r := &Registry{
		ConfigPath: cri.Registry.ConfigPath,
		Mirrors:    map[string][]string{},
		Configs:    map[string]*Auth{},
		Auths:      cri.Registry.Auths,
		Headers:    cri.Registry.Headers,
	}
	if r.Auths == nil {
		r.Auths = map[string]Auth{}
	}
	if r.Headers == nil {
		r.Headers = map[string][]string{}
	}
	for host, m := range cri.Registry.Mirrors {
		r.Mirrors[host] = m.Endpoint
		if m.Endpoint == nil {
			r.Mirrors[host] = []string{}
		}
	}
	for host, c := range cri.Registry.Configs {
		r.Configs[host] = c.Auth
	}
	return r
}

// materialise writes files, named relative to root, creating their directories.
func materialise(root string, files map[string]string) error {
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}
