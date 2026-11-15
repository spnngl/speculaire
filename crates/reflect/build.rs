//! Generates the reflector API's messages from `proto/` (D2, D105).

fn main() -> std::io::Result<()> {
    prost_build::compile_protos(&["proto/speculaire/reflect/v1/reflect.proto"], &["proto"])
}
