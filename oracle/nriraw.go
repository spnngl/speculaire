package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/net/multiplex"
	"github.com/containerd/ttrpc"
)

// RawCommand starts the raw mode: the oracle owns Socket and writes NRI's frames itself, for the two cases
// pkg/adaptation never sends (D162). Once a plugin connects, the plugin's frames on ConnID 2, where it calls
// the runtime, are read and never delivered: that connection stalls. ConnID 1 carries the runtime's calls to the
// plugin, as in NRI.
type RawCommand struct {
	Socket           string `json:"socket"`
	RequestTimeoutMS int64  `json:"request_timeout_ms"`
}

// AcceptCommand waits for a plugin to connect to the raw mode's socket.
type AcceptCommand struct {
	TimeoutMS int64 `json:"timeout_ms"`
}

// OversizeCommand writes one frame on ConnID whose length is `maxPayloadSize + 1`, header and payload.
type OversizeCommand struct {
	ConnID uint32 `json:"conn_id"`
}

// Written counts the bytes of a frame that reached the socket, and says why the rest did not.
type Written struct {
	Bytes int64  `json:"bytes"`
	Error string `json:"error,omitempty"`
}

// Stalled counts the frames the raw mode read off the stalled connection and never delivered.
type Stalled struct {
	Frames int   `json:"frames"`
	Bytes  int64 `json:"bytes"`
}

const (
	// A frame header is the ConnID and the payload length, big-endian (`pkg/net/multiplex/mux.go:139-140`,
	// `:251-252` at v0.12.3).
	frameHeaderLen = 8
	// The longest payload NRI's mux writes: a ttrpc message header and the longest message (`mux.go:142`,
	// `pkg/net/multiplex/ttrpc.go:27-28`).
	maxPayloadSize = 10 + 4<<20
	// rawWriteTimeout ends a write to a plugin that neither reads nor closes.
	rawWriteTimeout = 10 * time.Second
)

// rawRuntime is the raw mode: its own mux, which delivers ConnID 1 to a ttrpc client and stalls every other ConnID.
type rawRuntime struct {
	listener       *net.UnixListener
	requestTimeout time.Duration

	writeLock sync.Mutex
	trunk     net.Conn
	plugin    api.PluginService

	stallLock sync.Mutex
	stall     Stalled
}

func (s *nriSession) startRaw(c RawCommand) (any, error) {
	if s.runtime != nil || s.raw != nil {
		return nil, errors.New("the runtime is already started")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: c.Socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	s.raw = &rawRuntime{listener: listener, requestTimeout: milliseconds(c.RequestTimeoutMS)}
	return struct{}{}, nil
}

func (s *nriSession) accept(c AcceptCommand) (any, error) {
	if s.raw == nil {
		return nil, errors.New("the raw mode is not started")
	}
	return struct{}{}, s.raw.accept(milliseconds(c.TimeoutMS))
}

func (s *nriSession) oversize(c OversizeCommand) (any, error) {
	if s.raw == nil || s.raw.trunk == nil {
		return nil, errors.New("no plugin is connected in raw mode")
	}
	return s.raw.oversize(c.ConnID), nil
}

func (r *rawRuntime) accept(timeout time.Duration) error {
	if r.trunk != nil {
		return errors.New("a plugin is already connected")
	}
	if err := r.listener.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	trunk, err := r.listener.Accept()
	if err != nil {
		return err
	}
	// The ttrpc client speaks on one end of a pipe; the other end is framed on ConnID 1.
	ours, client := net.Pipe()
	r.trunk = trunk
	r.plugin = api.NewPluginClient(ttrpc.NewClient(client))
	go r.read(trunk, ours)
	go r.frame(ours)
	return nil
}

// read delivers the plugin's frames on ConnID 1 to the ttrpc client, and counts the others, which it drops.
func (r *rawRuntime) read(trunk, client net.Conn) {
	defer client.Close()
	var header [frameHeaderLen]byte
	for {
		if _, err := io.ReadFull(trunk, header[:]); err != nil {
			return
		}
		id := multiplex.ConnID(binary.BigEndian.Uint32(header[0:4]))
		length := int64(binary.BigEndian.Uint32(header[4:8]))
		if id == multiplex.PluginServiceConn {
			if _, err := io.CopyN(client, trunk, length); err != nil {
				return
			}
			continue
		}
		if _, err := io.CopyN(io.Discard, trunk, length); err != nil {
			return
		}
		r.stallLock.Lock()
		r.stall.Frames++
		r.stall.Bytes += length
		r.stallLock.Unlock()
	}
}

// frame writes what the ttrpc client sends as frames on ConnID 1.
func (r *rawRuntime) frame(client net.Conn) {
	buf := make([]byte, 64<<10)
	for {
		n, err := client.Read(buf)
		if n > 0 {
			if _, werr := r.write(uint32(multiplex.PluginServiceConn), uint32(n), buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// write writes one frame whose header says length, then payload, and returns the bytes written.
func (r *rawRuntime) write(id, length uint32, payload []byte) (int64, error) {
	r.writeLock.Lock()
	defer r.writeLock.Unlock()
	if r.trunk == nil {
		return 0, net.ErrClosed
	}
	if err := r.trunk.SetWriteDeadline(time.Now().Add(rawWriteTimeout)); err != nil {
		return 0, err
	}
	var header [frameHeaderLen]byte
	binary.BigEndian.PutUint32(header[0:4], id)
	binary.BigEndian.PutUint32(header[4:8], length)
	n, err := r.trunk.Write(header[:])
	if err != nil {
		return int64(n), err
	}
	m, err := r.trunk.Write(payload)
	return int64(n + m), err
}

func (r *rawRuntime) oversize(id uint32) Written {
	written, err := r.write(id, maxPayloadSize+1, make([]byte, maxPayloadSize+1))
	if err != nil {
		return Written{Bytes: written, Error: err.Error()}
	}
	return Written{Bytes: written}
}

// close closes the plugin's connection, and returns how many it closed.
func (r *rawRuntime) close() int {
	r.writeLock.Lock()
	defer r.writeLock.Unlock()
	if r.trunk == nil {
		return 0
	}
	r.trunk.Close()
	r.trunk = nil
	return 1
}

func (r *rawRuntime) create(request *api.CreateContainerRequest) error {
	if r.plugin == nil {
		return errors.New("no plugin is connected in raw mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.requestTimeout)
	defer cancel()
	_, err := r.plugin.CreateContainer(ctx, request)
	return err
}

func (r *rawRuntime) stalled() *Stalled {
	r.stallLock.Lock()
	defer r.stallLock.Unlock()
	stall := r.stall
	return &stall
}
