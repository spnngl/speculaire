use ttrpc_codegen_prost::{Codegen, Customize};

fn main() {
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    Codegen::new()
        .out_dir(&out)
        .inputs(["proto/api.proto"])
        .include("proto")
        .prost()
        .customize(Customize {
            async_all: true,
            ..Default::default()
        })
        .run()
        .expect("codegen");
    println!("cargo:rerun-if-changed=proto/api.proto");
}
