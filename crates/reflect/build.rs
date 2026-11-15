//! Generates the reflector API's messages, server and client from `proto/` (D2).

fn main() -> std::io::Result<()> {
    tonic_prost_build::configure()
        .build_transport(false)
        // D104: each message in its own frames, `src/codec.rs`.
        .codec_path("crate::codec::Unbatched")
        .compile_protos(&["proto/speculaire/reflect/v1/reflect.proto"], &["proto"])
}
