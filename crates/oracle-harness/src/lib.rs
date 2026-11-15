//! Test helper that runs `speculaire-oracle`, the Go binary that answers with containerd's own code (D29, D70).
//!
//! Each subcommand reads cases as JSON lines on stdin and prints one JSON line per case on stdout. A test asks the
//! oracle and the Rust port the same cases and requires the same answers.
//!
//! The tests find the binary through [`ENV`]: `just oracle` builds it and sets the variable. Without the variable
//! [`Oracle::from_env`] returns `None`, and the test skips, as it does in `just check`; with the variable and no
//! binary, it is an error, so a test cannot pass by skipping in the `oracle` job.

use std::io::{Read, Write as _};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// The environment variable that holds the path of the oracle binary.
pub const ENV: &str = "SPECULAIRE_ORACLE";

/// How long one [`Oracle::ask`] may run: a hung oracle fails its test, before the job's timeout hides which. The
/// slowest ask, CRI-O's 829 credential cases, takes about a minute.
const TIMEOUT: Duration = Duration::from_secs(300);

/// Why the oracle gave no answer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `SPECULAIRE_ORACLE` names a file that is not there.
    #[error("{ENV} names {}, which does not exist", .0.display())]
    Missing(PathBuf),
    /// The binary could not run, or its pipes failed.
    #[error("cannot run {}", path.display())]
    Run {
        /// The binary.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The binary did not exit in time, and was killed.
    #[error("{} did not answer within {after:?}", path.display())]
    Timeout {
        /// The binary.
        path: PathBuf,
        /// How long it had.
        after: Duration,
    },
    /// The binary exited with a failure.
    #[error("{} exited with {status}: {stderr}", path.display())]
    Exit {
        /// The binary.
        path: PathBuf,
        /// Its exit status.
        status: std::process::ExitStatus,
        /// What it printed on stderr.
        stderr: String,
    },
    /// A case could not be written, or an answer could not be read.
    #[error("case {index}: {message}")]
    Json {
        /// The position of the case.
        index: usize,
        /// What is wrong.
        message: String,
    },
    /// The oracle refused a case as input (not a case that containerd refuses: those are answers).
    #[error("case {index}: the oracle refused it: {message}")]
    Refused {
        /// The position of the case.
        index: usize,
        /// The oracle's message.
        message: String,
    },
    /// The oracle answered fewer or more lines than it was asked.
    #[error("asked {asked} cases, got {answered} answers")]
    Count {
        /// Cases written.
        asked: usize,
        /// Lines read.
        answered: usize,
    },
}

/// The oracle binary.
#[derive(Debug, Clone)]
pub struct Oracle {
    path: PathBuf,
    timeout: Duration,
}

impl Oracle {
    /// The binary [`ENV`] names, or `None` when the variable is unset.
    ///
    /// # Errors
    ///
    /// When the variable is set and names no file.
    pub fn from_env() -> Result<Option<Self>, Error> {
        let Some(path) = std::env::var_os(ENV).map(PathBuf::from) else {
            return Ok(None);
        };
        if !path.is_file() {
            return Err(Error::Missing(path));
        }
        Ok(Some(Self {
            path,
            timeout: TIMEOUT,
        }))
    }

    /// Runs `subcommand` on `cases`, and returns one answer per case, in order.
    ///
    /// # Errors
    ///
    /// When the binary cannot run, fails or outlasts its timeout, or answers a case with something other than an `A`.
    pub fn ask<C: Serialize, A: DeserializeOwned>(
        &self,
        subcommand: &str,
        cases: &[C],
    ) -> Result<Vec<A>, Error> {
        let run = |source| Error::Run {
            path: self.path.clone(),
            source,
        };
        let mut input = Vec::new();
        for (index, case) in cases.iter().enumerate() {
            serde_json::to_writer(&mut input, case).map_err(|e| Error::Json {
                index,
                message: e.to_string(),
            })?;
            input.push(b'\n');
        }
        let mut child = Command::new(&self.path)
            .arg(subcommand)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(run)?;
        let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
        let (Some(mut stdin), Some(stdout), Some(stderr)) = pipes else {
            return Err(run(std::io::Error::other("the child lacks a pipe")));
        };
        // The answers fill the pipe while the cases are still written: each pipe has its own thread, and this one
        // watches the clock. A killed child closes its pipes, which ends the threads.
        let (status, written, stdout, stderr) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || stdin.write_all(&input));
            let stdout = scope.spawn(|| read_all(stdout));
            let stderr = scope.spawn(|| read_all(stderr));
            let status = wait(&mut child, self.timeout);
            let joined = |handle: std::thread::ScopedJoinHandle<'_, std::io::Result<Vec<u8>>>| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err(std::io::Error::other("a reader panicked")))
            };
            (status, writer.join(), joined(stdout), joined(stderr))
        });
        let Some(status) = status.map_err(run)? else {
            return Err(Error::Timeout {
                path: self.path.clone(),
                after: self.timeout,
            });
        };
        if !status.success() {
            return Err(Error::Exit {
                path: self.path.clone(),
                status,
                stderr: String::from_utf8_lossy(&stderr.map_err(run)?).into_owned(),
            });
        }
        if let Ok(Err(source)) = written {
            return Err(run(source));
        }
        let stdout = stdout.map_err(run)?;
        let text = String::from_utf8_lossy(&stdout);
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() != cases.len() {
            return Err(Error::Count {
                asked: cases.len(),
                answered: lines.len(),
            });
        }
        lines
            .iter()
            .enumerate()
            .map(|(index, line)| answer(index, line))
            .collect()
    }
}

fn read_all(mut pipe: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).map(|_| bytes)
}

/// The child's exit status, or `None` once it has run for `limit` and been killed.
fn wait(child: &mut Child, limit: Duration) -> std::io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn answer<A: DeserializeOwned>(index: usize, line: &str) -> Result<A, Error> {
    let json = |e: serde_json::Error| Error::Json {
        index,
        message: e.to_string(),
    };
    let value: serde_json::Value = serde_json::from_str(line).map_err(json)?;
    if let Some(message) = value.get("oracle_error").and_then(|m| m.as_str()) {
        return Err(Error::Refused {
            index,
            message: message.to_owned(),
        });
    }
    serde_json::from_value(value).map_err(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variable_names_the_oracle_with_the_default_timeout() {
        // Only the `oracle` and `mutants` jobs set the variable (D79).
        let oracle = Oracle::from_env().expect("the variable names a file, or is unset");
        let expected = std::env::var_os(ENV).map(|path| (PathBuf::from(path), TIMEOUT));
        assert_eq!(oracle.map(|o| (o.path, o.timeout)), expected);
    }

    #[test]
    fn a_missing_binary_is_an_error() {
        let oracle = Oracle {
            path: PathBuf::from("/nonexistent/speculaire-oracle"),
            timeout: TIMEOUT,
        };
        let err = oracle.ask::<u8, u8>("version", &[1]).unwrap_err();
        assert!(matches!(err, Error::Run { .. }), "{err}");
    }

    #[test]
    fn an_oracle_that_hangs_is_killed_at_its_timeout() {
        // `sleep 600` stands for an oracle that never answers.
        let oracle = Oracle {
            path: PathBuf::from("sleep"),
            timeout: Duration::from_millis(100),
        };
        let started = Instant::now();
        let err = oracle.ask::<u8, u8>("600", &[1]).unwrap_err();
        assert!(matches!(err, Error::Timeout { .. }), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_failing_oracle_is_an_error_with_its_stderr() {
        let oracle = Oracle {
            path: PathBuf::from("sh"),
            timeout: TIMEOUT,
        };
        let err = oracle.ask::<u8, u8>("-c", &[1]).unwrap_err();
        assert!(
            matches!(&err, Error::Exit { stderr, .. } if !stderr.is_empty()),
            "{err}"
        );
    }

    #[test]
    fn each_case_gets_the_answer_on_its_line() {
        // `cat -` answers each case with itself.
        let oracle = Oracle {
            path: PathBuf::from("cat"),
            timeout: TIMEOUT,
        };
        assert_eq!(oracle.ask::<u8, u8>("-", &[1, 2]).unwrap(), vec![1, 2]);
    }

    #[test]
    fn the_oracle_refusing_a_case_is_an_error_naming_it() {
        let err = answer::<u8>(3, r#"{"oracle_error":"bad"}"#).unwrap_err();
        assert_eq!(err.to_string(), "case 3: the oracle refused it: bad");
    }

    #[test]
    fn an_answer_of_another_shape_is_an_error_naming_its_case() {
        let err = answer::<u8>(2, r#""text""#).unwrap_err();
        assert!(matches!(err, Error::Json { index: 2, .. }), "{err}");
    }

    #[test]
    fn answers_are_read_in_the_shape_asked() {
        assert_eq!(answer::<Vec<u8>>(0, "[1,2]").unwrap(), vec![1, 2]);
    }
}
