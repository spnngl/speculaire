//! `fake-runtime <socket> [<containerd version>]`: a fake containerd on `socket` until it is killed, for the
//! conformance run, where no runtime exists (D87).

use std::path::Path;
use std::process::ExitCode;

use speculaire_fake_runtime::{Answers, Fake};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(socket) = args.next() else {
        eprintln!("usage: fake-runtime <socket> [<containerd version>]");
        return ExitCode::from(2);
    };
    let version = args.next().unwrap_or_else(|| "v2.4.2".to_owned());
    let _fake = match Fake::start(Path::new(&socket), Answers::containerd(&version)) {
        Ok(fake) => fake,
        Err(err) => {
            eprintln!("fake-runtime: {socket}: {err}");
            return ExitCode::FAILURE;
        }
    };
    loop {
        std::thread::park();
    }
}
