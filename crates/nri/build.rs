//! Generates NRI's and ttrpc's messages from `proto/` (D9, D166).

fn main() -> std::io::Result<()> {
    prost_build::compile_protos(
        &[
            "proto/nri/pkg/api/v1alpha1/api.proto",
            "proto/ttrpc/request.proto",
        ],
        &["proto"],
    )
}
