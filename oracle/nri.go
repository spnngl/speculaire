package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/containerd/nri/pkg/adaptation"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/net/multiplex"
	"github.com/containerd/nri/pkg/stub"
	validator "github.com/containerd/nri/plugins/default-validator"
	"github.com/containerd/ttrpc"
)

// NRIVersionCase is one `nri-version` case: a runtime as it names itself in `Configure`, and its version.
type NRIVersionCase struct {
	Runtime string `json:"runtime"`
	Version string `json:"version"`
}

// NRIVersionAnswer is the NRI version NRI infers for the runtime, or why it cannot.
type NRIVersionAnswer struct {
	NRIVersion string `json:"nri_version,omitempty"`
	Error      string `json:"error,omitempty"`
}

func nriVersionCase(line []byte) (any, error) {
	var c NRIVersionCase
	if err := json.Unmarshal(line, &c); err != nil {
		return nil, err
	}
	version, err := api.InferVersionFromRuntime(c.Runtime, c.Version)
	if err != nil {
		return NRIVersionAnswer{Error: err.Error()}, nil
	}
	return NRIVersionAnswer{NRIVersion: version}, nil
}

// StartCommand starts a runtime on pkg/adaptation, listening on Socket, as containerd and CRI-O do.
type StartCommand struct {
	Socket         string `json:"socket"`
	RuntimeName    string `json:"runtime_name"`
	RuntimeVersion string `json:"runtime_version"`
	// NRIVersion replaces the NRI version `Configure` announces, by default the linked module's. CRI-O 1.35 and 1.36
	// announce none (D64).
	NRIVersion            *string  `json:"nri_version"`
	RegistrationTimeoutMS int64    `json:"registration_timeout_ms"`
	RequestTimeoutMS      int64    `json:"request_timeout_ms"`
	RequiredPlugins       []string `json:"required_plugins"`
}

// StateCommand replaces the pods and containers each connecting plugin gets in `Synchronize`.
type StateCommand struct {
	Pods       []PodCase       `json:"pods"`
	Containers []ContainerCase `json:"containers"`
}

// StubCommand connects NRI's own `pkg/stub` plugin to the runtime, from inside the oracle.
type StubCommand struct {
	Name  string `json:"name"`
	Index string `json:"index"`
	// Reject, when set, is the error the plugin answers each `CreateContainer` with.
	Reject string `json:"reject"`
}

// StubAnswer is what the stub learnt from `Configure`.
type StubAnswer struct {
	RuntimeNRIVersion     string `json:"runtime_nri_version"`
	RegistrationTimeoutMS int64  `json:"registration_timeout_ms"`
	RequestTimeoutMS      int64  `json:"request_timeout_ms"`
}

// WaitCommand waits until Plugins plugins are connected and synchronized.
type WaitCommand struct {
	Plugins   int   `json:"plugins"`
	TimeoutMS int64 `json:"timeout_ms"`
}

// CreateCommand relays `CreateContainer` to the plugins.
type CreateCommand struct {
	Pod       PodCase       `json:"pod"`
	Container ContainerCase `json:"container"`
}

// Rejected is the error that refused a container. A container the plugins allow is answered `"allowed"`.
type Rejected struct {
	Rejected string `json:"rejected"`
}

// PodCase is a pod sandbox as the runtime describes it to plugins.
type PodCase struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	UID         string            `json:"uid"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations"`
}

// ContainerCase is a container as the runtime describes it to plugins.
type ContainerCase struct {
	ID          string            `json:"id"`
	PodID       string            `json:"pod_id"`
	Name        string            `json:"name"`
	Image       *ImageCase        `json:"image"`
	Annotations map[string]string `json:"annotations"`
}

// ImageCase is the image of a container, which runtimes send from NRI v0.12.2 on.
type ImageCase struct {
	Name         string `json:"name"`
	Digest       string `json:"digest"`
	ConfigDigest string `json:"config_digest"`
}

// Report lists the connected plugins and, in raw mode, the frames left unread.
type Report struct {
	Plugins []PluginReport `json:"plugins"`
	Stalled *Stalled       `json:"stalled,omitempty"`
}

// PluginReport is one connected plugin.
type PluginReport struct {
	// Name is the plugin's index and name, as `01-speculaire`.
	Name string `json:"name"`
	// Events are the events the plugin is subscribed to after `Configure`, as `CREATE_CONTAINER`.
	Events []string `json:"events"`
	// SynchronizeRequests counts the `Synchronize` requests that reached a plugin of this name since the runtime
	// started or last closed its connections.
	SynchronizeRequests int `json:"synchronize_requests"`
}

// Closed counts the plugin connections a `close` command closed.
type Closed struct {
	Closed int `json:"closed"`
}

// nriSession is one `nri-runtime` process: a runtime on pkg/adaptation, or the raw mode.
type nriSession struct {
	runtime *adaptation.Adaptation
	raw     *rawRuntime
	syncs   *syncCounter

	stateLock  sync.Mutex
	pods       []*api.PodSandbox
	containers []*api.Container
}

func newNRISession() *nriSession {
	return &nriSession{syncs: &syncCounter{requests: map[string]int{}}}
}

// answer runs one command: a JSON object whose only key names it.
func (s *nriSession) answer(line []byte) (any, error) {
	var command map[string]json.RawMessage
	if err := json.Unmarshal(line, &command); err != nil {
		return nil, err
	}
	if len(command) != 1 {
		return nil, fmt.Errorf("a command has one key, this one %d", len(command))
	}
	for name, args := range command {
		switch name {
		case "start":
			return with(args, s.start)
		case "state":
			return with(args, s.state)
		case "stub":
			return with(args, s.stub)
		case "wait":
			return with(args, s.wait)
		case "create":
			return with(args, s.create)
		case "close":
			return s.closePlugins()
		case "report":
			report, err := s.report()
			return report, err
		case "raw":
			return with(args, s.startRaw)
		case "accept":
			return with(args, s.accept)
		case "oversize":
			return with(args, s.oversize)
		}
		return nil, fmt.Errorf("unknown command %q", name)
	}
	panic("unreachable: the command has one key")
}

func with[C any](args json.RawMessage, run func(C) (any, error)) (any, error) {
	var c C
	if err := json.Unmarshal(args, &c); err != nil {
		return nil, err
	}
	return run(c)
}

func (s *nriSession) start(c StartCommand) (any, error) {
	if s.runtime != nil || s.raw != nil {
		return nil, errors.New("the runtime is already started")
	}
	adaptation.SetPluginRegistrationTimeout(milliseconds(c.RegistrationTimeoutMS))
	adaptation.SetPluginRequestTimeout(milliseconds(c.RequestTimeoutMS))
	options := []adaptation.Option{
		adaptation.WithSocketPath(c.Socket),
		// No pre-installed plugins: the empty path names no directory.
		adaptation.WithPluginPath(""),
		adaptation.WithMetrics(s.syncs),
	}
	if len(c.RequiredPlugins) > 0 {
		options = append(options, adaptation.WithDefaultValidator(&validator.DefaultValidatorConfig{
			Enable:          true,
			RequiredPlugins: c.RequiredPlugins,
		}))
	}
	runtime, err := adaptation.New(c.RuntimeName, c.RuntimeVersion, s.synchronize, noUpdates, options...)
	if err != nil {
		return nil, err
	}
	if c.NRIVersion != nil {
		unexported(reflect.ValueOf(runtime), "nriVersion").SetString(*c.NRIVersion)
	}
	if err := runtime.Start(); err != nil {
		return nil, err
	}
	s.runtime = runtime
	return struct{}{}, nil
}

func (s *nriSession) state(c StateCommand) (any, error) {
	pods := make([]*api.PodSandbox, 0, len(c.Pods))
	for _, pod := range c.Pods {
		pods = append(pods, pod.api())
	}
	containers := make([]*api.Container, 0, len(c.Containers))
	for _, container := range c.Containers {
		containers = append(containers, container.api(api.ContainerState_CONTAINER_RUNNING))
	}
	s.stateLock.Lock()
	defer s.stateLock.Unlock()
	s.pods, s.containers = pods, containers
	return struct{}{}, nil
}

// synchronize hands the loaded state to a connecting plugin, which pkg/adaptation splits as it must.
func (s *nriSession) synchronize(ctx context.Context, plugin adaptation.SyncCB) error {
	s.stateLock.Lock()
	pods, containers := s.pods, s.containers
	s.stateLock.Unlock()
	_, err := plugin(ctx, pods, containers)
	return err
}

func noUpdates(context.Context, []*api.ContainerUpdate) ([]*api.ContainerUpdate, error) {
	return nil, nil
}

func (s *nriSession) stub(c StubCommand) (any, error) {
	if s.runtime == nil {
		return nil, errors.New("no runtime is started")
	}
	plugin, err := stub.New(stubPlugin{reject: c.Reject},
		stub.WithPluginName(c.Name),
		stub.WithPluginIdx(c.Index),
		stub.WithSocketPath(s.socket()),
	)
	if err != nil {
		return nil, err
	}
	if err := plugin.Start(context.Background()); err != nil {
		return nil, err
	}
	return StubAnswer{
		RuntimeNRIVersion:     plugin.RuntimeNRIVersion(),
		RegistrationTimeoutMS: plugin.RegistrationTimeout().Milliseconds(),
		RequestTimeoutMS:      plugin.RequestTimeout().Milliseconds(),
	}, nil
}

func (s *nriSession) socket() string {
	return unexported(reflect.ValueOf(s.runtime), "socketPath").String()
}

// stubPlugin is the smallest plugin on pkg/stub: it takes the state, and allows or rejects every container.
type stubPlugin struct {
	reject string
}

func (stubPlugin) Synchronize(context.Context, []*api.PodSandbox, []*api.Container) ([]*api.ContainerUpdate, error) {
	return nil, nil
}

func (p stubPlugin) CreateContainer(context.Context, *api.PodSandbox, *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	if p.reject != "" {
		return nil, nil, errors.New(p.reject)
	}
	return nil, nil, nil
}

func (s *nriSession) wait(c WaitCommand) (any, error) {
	deadline := time.Now().Add(milliseconds(c.TimeoutMS))
	for {
		report, err := s.report()
		if err != nil {
			return nil, err
		}
		connected := len(report.Plugins)
		if connected == c.Plugins {
			return report, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%d plugins connected after %d ms, not %d", connected, c.TimeoutMS, c.Plugins)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *nriSession) create(c CreateCommand) (any, error) {
	if c.Container.PodID == "" {
		c.Container.PodID = c.Pod.ID
	}
	request := &api.CreateContainerRequest{
		Pod:       c.Pod.api(),
		Container: c.Container.api(api.ContainerState_CONTAINER_CREATED),
	}
	var err error
	switch {
	case s.runtime != nil:
		_, err = s.runtime.CreateContainer(context.Background(), request)
	case s.raw != nil:
		err = s.raw.create(request)
	default:
		return nil, errors.New("no runtime is started")
	}
	if err != nil {
		return Rejected{Rejected: err.Error()}, nil
	}
	return "allowed", nil
}

// closePlugins closes the connection of every plugin, as a runtime that exits does: pkg/adaptation's `Stop` leaves
// external plugins connected (`pkg/adaptation/plugin.go:387-403` at v0.12.3).
func (s *nriSession) closePlugins() (any, error) {
	if s.raw != nil {
		return Closed{Closed: s.raw.close()}, nil
	}
	closed := 0
	err := s.eachPlugin(func(plugin reflect.Value, mux multiplex.Mux) {
		if !unexported(plugin, "closed").Bool() {
			mux.Close()
			closed++
		}
	})
	s.syncs.reset()
	return Closed{Closed: closed}, err
}

func (s *nriSession) report() (Report, error) {
	report := Report{Plugins: []PluginReport{}}
	if s.raw != nil {
		report.Stalled = s.raw.stalled()
	}
	err := s.eachPlugin(func(plugin reflect.Value, _ multiplex.Mux) {
		if unexported(plugin, "closed").Bool() {
			return
		}
		name := unexported(plugin, "idx").String() + "-" + unexported(plugin, "base").String()
		mask := api.EventMask(unexported(plugin, "events").Int())
		events := []string{}
		for e := api.Event(1); e < api.Event_LAST; e++ {
			if mask.IsSet(e) {
				events = append(events, e.String())
			}
		}
		report.Plugins = append(report.Plugins, PluginReport{
			Name:                name,
			Events:              events,
			SynchronizeRequests: s.syncs.count(name),
		})
	})
	return report, err
}

// eachPlugin calls visit with each external plugin of the runtime, locked, and its connection. pkg/adaptation exports
// neither (`pkg/adaptation/plugin.go:53-71` at v0.12.3): a release that renames a field makes the oracle panic, which
// its tests show.
func (s *nriSession) eachPlugin(visit func(plugin reflect.Value, mux multiplex.Mux)) error {
	if s.runtime == nil {
		if s.raw != nil {
			return nil
		}
		return errors.New("no runtime is started")
	}
	s.runtime.Lock()
	defer s.runtime.Unlock()
	plugins := unexported(reflect.ValueOf(s.runtime), "plugins")
	for i := range plugins.Len() {
		plugin := plugins.Index(i)
		// A builtin plugin, as the default validator, has no connection.
		mux, external := unexported(plugin, "mux").Interface().(multiplex.Mux)
		if !external {
			continue
		}
		lock := unexported(plugin, "Mutex").Addr().Interface().(*sync.Mutex)
		lock.Lock()
		visit(plugin, mux)
		lock.Unlock()
	}
	return nil
}

// unexported is the field name of the struct pointer refers to, readable and settable.
func unexported(pointer reflect.Value, name string) reflect.Value {
	field := pointer.Elem().FieldByName(name)
	if !field.IsValid() {
		panic(fmt.Sprintf("%s has no field %s", pointer.Type(), name))
	}
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}

// syncCounter counts the `Synchronize` requests that reach each plugin, through pkg/adaptation's metrics hook.
type syncCounter struct {
	sync.Mutex
	requests map[string]int
}

func (c *syncCounter) RecordPluginInvocation(plugin, operation string, err error) {
	// An oversized request never left the runtime: pkg/adaptation splits it and tries again.
	var oversized *ttrpc.OversizedMessageErr
	if operation != "Synchronize" || errors.As(err, &oversized) {
		return
	}
	c.Lock()
	defer c.Unlock()
	c.requests[plugin]++
}

func (c *syncCounter) count(plugin string) int {
	c.Lock()
	defer c.Unlock()
	return c.requests[plugin]
}

func (c *syncCounter) reset() {
	c.Lock()
	defer c.Unlock()
	clear(c.requests)
}

func (*syncCounter) RecordPluginLatency(string, string, time.Duration) {}

func (*syncCounter) RecordPluginAdjustments(string, string, *api.ContainerAdjustment, int, int) {}

func (*syncCounter) UpdatePluginCount(int) {}

func (p PodCase) api() *api.PodSandbox {
	return &api.PodSandbox{
		Id:          p.ID,
		Name:        p.Name,
		Uid:         p.UID,
		Namespace:   p.Namespace,
		Annotations: p.Annotations,
	}
}

func (c ContainerCase) api(state api.ContainerState) *api.Container {
	container := &api.Container{
		Id:           c.ID,
		PodSandboxId: c.PodID,
		Name:         c.Name,
		State:        state,
		Annotations:  c.Annotations,
	}
	if c.Image != nil {
		container.Image = &api.Image{Name: c.Image.Name, Digest: c.Image.Digest, ConfigDigest: c.Image.ConfigDigest}
	}
	return container
}

func milliseconds(ms int64) time.Duration {
	return time.Duration(ms) * time.Millisecond
}
