//! `fake-runtime <socket> <NRI socket> [<containerd version>]`: a fake containerd on `socket` and its NRI on
//! `NRI socket` until it is killed, for the conformance run, where no runtime exists (D87, D168).

use std::path::Path;
use std::process::ExitCode;

use speculaire_fake_runtime::{Answers, Fake};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(socket), Some(nri)) = (args.next(), args.next()) else {
        eprintln!("usage: fake-runtime <socket> <NRI socket> [<containerd version>]");
        return ExitCode::from(2);
    };
    let version = args.next().unwrap_or_else(|| "v2.4.2".to_owned());
    let answers = Answers::containerd(&version);
    let _fakes = match (
        Fake::start(Path::new(&socket), answers.clone()),
        Fake::start_nri(Path::new(&nri), answers),
    ) {
        (Ok(fake), Ok(nri)) => (fake, nri),
        (Err(err), _) => {
            eprintln!("fake-runtime: {socket}: {err}");
            return ExitCode::FAILURE;
        }
        (_, Err(err)) => {
            eprintln!("fake-runtime: {nri}: {err}");
            return ExitCode::FAILURE;
        }
    };
    loop {
        std::thread::park();
    }
}
