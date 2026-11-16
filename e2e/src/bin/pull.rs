//! Pulls the image its argument names through Docker Hub's mirrors and prints the reference it pulled, for
//! `just e2e-up` (D120).

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(image), None) = (args.next(), args.next()) else {
        eprintln!("usage: pull <image>");
        return ExitCode::FAILURE;
    };
    match e2e::hub::pulled(&image) {
        Ok(pulled) => {
            println!("{pulled}");
            ExitCode::SUCCESS
        }
        Err(failure) => {
            eprintln!("e2e: {failure}");
            ExitCode::FAILURE
        }
    }
}
