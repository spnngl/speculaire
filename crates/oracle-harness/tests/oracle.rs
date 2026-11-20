//! The NRI subcommands of `speculaire-oracle` against NRI's own code (D29, D70): `nri-version` against the
//! inference table of `pkg/api`, and `nri-runtime` against NRI's own `pkg/stub` plugin and a client that reads the raw
//! mode's frames. Without `SPECULAIRE_ORACLE` the tests skip, as in `just check`; `just oracle` sets it.

#![expect(clippy::panic, reason = "a test file: its helpers report by panicking")]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use speculaire_oracle_harness::Oracle;
use speculaire_oracle_harness::nri::{
    Container, Create, Image, Pod, Start, State, Stub, Verdict, VersionAnswer, VersionCase,
};

/// The longest payload of NRI's mux (`pkg/net/multiplex/mux.go:142` at v0.12.3).
const MAX_PAYLOAD: usize = 10 + (4 << 20);

/// A plugin connects, registers and synchronizes well within this.
const SETTLE: Duration = Duration::from_secs(30);

fn oracle() -> Option<Oracle> {
    match Oracle::from_env() {
        Ok(Some(oracle)) => Some(oracle),
        Ok(None) => {
            eprintln!(
                "skipped: {} is not set (`just oracle` sets it)",
                speculaire_oracle_harness::ENV
            );
            None
        }
        Err(e) => panic!("{e}"),
    }
}

fn socket(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("nri.sock")
}

fn speculaire(reject: Option<&str>) -> Stub {
    Stub {
        name: "speculaire".to_owned(),
        index: "10".to_owned(),
        reject: reject.map(str::to_owned),
    }
}

fn create() -> Create {
    let pod = Pod {
        id: "pod-0".to_owned(),
        name: "web".to_owned(),
        namespace: "default".to_owned(),
        ..Pod::default()
    };
    let container = Container {
        id: "container-0".to_owned(),
        name: "nginx".to_owned(),
        image: Some(Image {
            name: "docker.io/library/nginx:1.27".to_owned(),
            ..Image::default()
        }),
        annotations: BTreeMap::from([(
            "io.kubernetes.cri.image-name".to_owned(),
            "nginx".to_owned(),
        )]),
        ..Container::default()
    };
    Create { pod, container }
}

#[test]
fn nri_infers_the_version_each_runtime_links() {
    let Some(oracle) = oracle() else { return };
    let case = |runtime: &str, version: &str| VersionCase {
        runtime: runtime.to_owned(),
        version: version.to_owned(),
    };
    let cases = [
        case("containerd", "v2.3.7"),
        case("containerd", "v2.4.2"),
        case("cri-o", "v1.35.10"),
        case("docker", "v29.0.0"),
    ];
    let answers: Vec<VersionAnswer> = oracle.ask("nri-version", &cases).unwrap();
    let v0_11 = VersionAnswer::NriVersion("v0.11.0".to_owned());
    assert_eq!(answers[..3], [v0_11.clone(), v0_11.clone(), v0_11]);
    assert!(
        matches!(&answers[3], VersionAnswer::Error(e) if e.contains("docker")),
        "{:?}",
        answers[3]
    );
}

#[test]
fn the_runtime_drives_a_stub_through_configure_split_synchronize_and_create() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut runtime = oracle.nri_runtime().unwrap();
    let mut start = Start::new(socket(&dir), "containerd", "v2.4.2");
    start.registration_timeout = Duration::from_secs(3);
    start.request_timeout = Duration::from_millis(1500);
    runtime.start(&start).unwrap();
    // 10 MiB of containers: over twice ttrpc's 4 MiB limit, so pkg/adaptation splits them in at least three.
    runtime.state(&State::padded(40, 400, 25 << 10)).unwrap();

    let rejection = "speculaire: no verified signature";
    let configured = runtime.stub(&speculaire(Some(rejection))).unwrap();
    assert_eq!(configured.registration_timeout, Duration::from_secs(3));
    assert_eq!(configured.request_timeout, Duration::from_millis(1500));
    assert_eq!(configured.runtime_nri_version, "v0.12.3");

    let report = runtime.wait(1, SETTLE).unwrap();
    let [plugin] = &report.plugins[..] else {
        panic!("{report:?}")
    };
    assert_eq!(plugin.name, "10-speculaire");
    assert_eq!(plugin.events, ["CREATE_CONTAINER"]);
    assert!(plugin.synchronize_requests >= 3, "{plugin:?}");
    eprintln!(
        "{} took {} Synchronize requests",
        plugin.name, plugin.synchronize_requests
    );

    match runtime.create(&create()).unwrap() {
        Verdict::Rejected(e) => assert!(e.contains(rejection), "{e}"),
        Verdict::Allowed => panic!("the stub rejects every container"),
    }
    assert_eq!(runtime.close().unwrap(), 1);
    assert_eq!(runtime.wait(0, SETTLE).unwrap().plugins, []);
}

#[test]
fn a_stub_infers_the_nri_version_cri_o_leaves_empty() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut runtime = oracle.nri_runtime().unwrap();
    let mut start = Start::new(socket(&dir), "cri-o", "v1.35.10");
    start.nri_version = Some(String::new());
    runtime.start(&start).unwrap();
    let configured = runtime.stub(&speculaire(None)).unwrap();
    assert_eq!(configured.runtime_nri_version, "v0.11.0");
    runtime.wait(1, SETTLE).unwrap();
    assert_eq!(runtime.create(&create()).unwrap(), Verdict::Allowed);
}

#[test]
fn a_required_plugin_missing_rejects_every_container() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut runtime = oracle.nri_runtime().unwrap();
    let mut start = Start::new(socket(&dir), "containerd", "v2.4.2");
    start.required_plugins = vec!["speculaire".to_owned()];
    runtime.start(&start).unwrap();
    match runtime.create(&create()).unwrap() {
        Verdict::Rejected(e) => assert!(e.contains("required plugin"), "{e}"),
        Verdict::Allowed => panic!("no plugin is connected"),
    }
}

/// One frame of NRI's mux: `ConnID` and payload length, big-endian, then the payload.
fn frame(conn: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("a test frame is short");
    [&conn.to_be_bytes()[..], &length.to_be_bytes(), payload].concat()
}

/// Reads one frame header off `stream`: its `ConnID` and length.
fn header(stream: &mut UnixStream) -> (u32, usize) {
    let mut header = [0; 8];
    stream
        .read_exact(&mut header)
        .expect("the oracle writes whole frames");
    let [c0, c1, c2, c3, l0, l1, l2, l3] = header;
    let length = u32::from_be_bytes([l0, l1, l2, l3]);
    (
        u32::from_be_bytes([c0, c1, c2, c3]),
        usize::try_from(length).expect("usize holds u32"),
    )
}

#[test]
fn the_raw_mode_writes_an_oversized_frame_as_is() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut runtime = oracle.nri_runtime().unwrap();
    runtime.raw(&socket(&dir), Duration::from_secs(5)).unwrap();
    let mut plugin = UnixStream::connect(socket(&dir)).unwrap();
    runtime.accept(SETTLE).unwrap();

    // The frame is larger than the socket's buffer: it is read while the oracle writes it.
    let reader = std::thread::spawn(move || {
        let (conn, length) = header(&mut plugin);
        let mut payload = vec![0; length];
        plugin.read_exact(&mut payload).unwrap();
        (conn, length)
    });
    let written = runtime.oversize(1).unwrap();
    assert_eq!(reader.join().unwrap(), (1, MAX_PAYLOAD + 1));
    assert_eq!(written.error, None);
    assert_eq!(written.bytes, u64::try_from(8 + MAX_PAYLOAD + 1).unwrap());
}

#[test]
fn the_raw_mode_stalls_conn_2_while_it_answers_on_conn_1() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut runtime = oracle.nri_runtime().unwrap();
    runtime.raw(&socket(&dir), Duration::from_secs(5)).unwrap();
    let mut plugin = UnixStream::connect(socket(&dir)).unwrap();
    runtime.accept(SETTLE).unwrap();

    // The plugin calls the runtime on ConnID 2, three times, and is never answered; it answers the runtime's
    // CreateContainer on ConnID 1.
    let stalled: Vec<u8> = (0..3).flat_map(|_| frame(2, &[7; 100])).collect();
    plugin.write_all(&stalled).unwrap();
    let answerer = std::thread::spawn(move || {
        // A ttrpc message: length, stream ID, type (1 request, 2 response), flags, then the message.
        let mut message = Vec::new();
        while message.len() < 10
            || message.len()
                < 10 + usize::try_from(u32::from_be_bytes(message[..4].try_into().unwrap()))
                    .unwrap()
        {
            let (conn, length) = header(&mut plugin);
            assert_eq!(conn, 1, "the runtime calls the plugin on ConnID 1");
            let mut payload = vec![0; length];
            plugin.read_exact(&mut payload).unwrap();
            message.extend_from_slice(&payload);
        }
        assert_eq!(message[8], 1, "a request");
        // An empty response with the request's stream ID: OK, and an empty CreateContainerResponse.
        let mut response = [0_u8; 10];
        response[4..8].copy_from_slice(&message[4..8]);
        response[8] = 2;
        plugin.write_all(&frame(1, &response)).unwrap();
        message
    });
    assert_eq!(runtime.create(&create()).unwrap(), Verdict::Allowed);
    let request = answerer.join().unwrap();
    let method = b"CreateContainer";
    assert!(request.windows(method.len()).any(|w| w == method));
    let stall = runtime.report().unwrap().stalled.unwrap();
    assert_eq!((stall.frames, stall.bytes), (3, 300));
    assert_eq!(runtime.close().unwrap(), 1);
}
