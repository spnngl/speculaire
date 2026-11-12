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

// nriPlugin is containerd's NRI plugin.
const nriPlugin = "io.containerd.nri.v1.nri"

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

// Plugins is what the agent reads of the plugin sections besides the registry.
type Plugins struct {
	DiscardUnpackedLayers bool `json:"discard_unpacked_layers"`
	NRI                   NRI  `json:"nri"`
}

// NRI is the NRI plugin's settings, and whether the daemon's `disabled_plugins` names it.
type NRI struct {
	Disable            bool     `json:"disable"`
	DisableConnections bool     `json:"disable_connections"`
	PluginDisabled     bool     `json:"plugin_disabled"`
	RequiredPlugins    []string `json:"required_plugins"`
}

// ConfigAnswer is the answer to a ConfigCase: the registry section and the other settings, or the loader's refusal.
type ConfigAnswer struct {
	Registry *Registry `json:"registry,omitempty"`
	Plugins  *Plugins  `json:"plugins,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// criImages is the part of the CRI image config the oracle reads besides the registry.
type criImages struct {
	DiscardUnpackedLayers bool `json:"discardUnpackedLayers"`
}

// criNRI is the part of the NRI config the oracle reads, through its JSON tags.
type criNRI struct {
	Disable            bool `json:"disable"`
	DisableConnections bool `json:"disableConnections"`
	DefaultValidator   *struct {
		RequiredPlugins []string
	} `json:"defaultValidator"`
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
	images, err := decodePlugin(ctx, graph, config, imagesPlugin)
	if err != nil {
		return ConfigAnswer{Error: err.Error()}
	}
	nri, err := decodePlugin(ctx, graph, config, nriPlugin)
	if err != nil {
		return ConfigAnswer{Error: err.Error()}
	}
	return ConfigAnswer{Registry: registryOf(images), Plugins: pluginsOf(images, nri, config)}
}

// decodePlugin decodes the section of the plugin with this URI as the daemon does.
func decodePlugin(ctx context.Context, graph []plugin.Registration, config *srvconfig.Config, uri string) (any, error) {
	for _, p := range graph {
		if p.URI() != uri {
			continue
		}
		// Registration.Config is shared by every case: decode into a deep copy of it, since a decode writes through
		// the pointers a config holds.
		fresh := reflect.New(reflect.TypeOf(p.Config).Elem())
		fresh.Elem().Set(deepCopy(reflect.ValueOf(p.Config).Elem()))
		if _, err := config.Decode(ctx, p.URI(), fresh.Interface()); err != nil {
			return nil, err
		}
		return fresh.Interface(), nil
	}
	return nil, fmt.Errorf("the daemon registers no %s plugin", uri)
}

// deepCopy copies a value with the structs, pointers, slices and maps it holds.
func deepCopy(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		c := reflect.New(v.Type().Elem())
		c.Elem().Set(deepCopy(v.Elem()))
		return c
	case reflect.Struct:
		c := reflect.New(v.Type()).Elem()
		for i := range v.NumField() {
			if c.Field(i).CanSet() {
				c.Field(i).Set(deepCopy(v.Field(i)))
			}
		}
		return c
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		c := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := range v.Len() {
			c.Index(i).Set(deepCopy(v.Index(i)))
		}
		return c
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		c := reflect.MakeMapWithSize(v.Type(), v.Len())
		for _, k := range v.MapKeys() {
			c.SetMapIndex(k, deepCopy(v.MapIndex(k)))
		}
		return c
	default:
		return v
	}
}

func pluginsOf(images, nri any, config *srvconfig.Config) *Plugins {
	var i criImages
	var n criNRI
	for _, c := range []struct {
		from any
		to   any
	}{{images, &i}, {nri, &n}} {
		raw, err := json.Marshal(c.from)
		if err != nil {
			panic(err)
		}
		if err := json.Unmarshal(raw, c.to); err != nil {
			panic(err)
		}
	}
	required := []string{}
	if n.DefaultValidator != nil && n.DefaultValidator.RequiredPlugins != nil {
		required = n.DefaultValidator.RequiredPlugins
	}
	return &Plugins{
		DiscardUnpackedLayers: i.DiscardUnpackedLayers,
		NRI: NRI{
			Disable:            n.Disable,
			DisableConnections: n.DisableConnections,
			PluginDisabled:     slices.Contains(config.DisabledPlugins, nriPlugin),
			RequiredPlugins:    required,
		},
	}
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
