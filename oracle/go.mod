// The test oracle (D29): containerd at the newest supported 2.4.x, and the NRI that release requires.
module github.com/spnngl/speculaire/oracle

go 1.26.6

require (
	github.com/containerd/containerd/v2 v2.4.2
	github.com/containerd/nri v0.12.3
)

require (
	github.com/containerd/log v0.2.0 // indirect
	github.com/containerd/ttrpc v1.2.9 // indirect
	github.com/knqyf263/go-plugin v0.9.0 // indirect
	github.com/opencontainers/runtime-spec v1.3.0 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260825221802-da73d73af1c5 // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
