//! Spike 00: proves a static musl binary can do what the agent does inside its D53 unit.
use std::fs;
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

fn step<T, E: std::fmt::Display>(name: &str, r: Result<T, E>) -> Result<T, String> {
    match r {
        Ok(v) => {
            println!("ok   {name}");
            Ok(v)
        }
        Err(e) => Err(format!("FAIL {name}: {e}")),
    }
}

fn run() -> Result<(), String> {
    let _l = step("bind [::]:7482", TcpListener::bind("[::]:7482"))?;
    step("connect containerd.sock", UnixStream::connect("/run/containerd/containerd.sock"))?;
    step("connect nri.sock", UnixStream::connect("/var/run/nri/nri.sock"))?;
    step("write /var/lib/speculaire", fs::write("/var/lib/speculaire/hello", b"x"))?;
    step("write /run/speculaire", fs::write("/run/speculaire/hello", b"x"))?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(m) => {
            eprintln!("{m}");
            ExitCode::FAILURE
        }
    }
}
