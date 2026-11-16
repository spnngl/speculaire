//! Docker Hub's images through its mirrors (D120): an image of Docker Hub comes from `mirror.gcr.io`, then, for an
//! official image, from `public.ecr.aws/docker`, and from Docker Hub last, whose anonymous pulls a CI runner shares a
//! rate limit for. Every image is pinned by digest, so each source serves the same bytes or none. The nodes' runtimes
//! take the same mirrors from their node image (`e2e/node/`), and the justfile's recipes from its `hub-pull` (D122).

use crate::Failure;
use crate::registry::{docker, fail};

/// Where to pull `image`, a full reference, from, in order.
#[must_use]
pub fn sources(image: &str) -> Vec<String> {
    let Some(path) = image.strip_prefix("docker.io/") else {
        return vec![image.to_owned()];
    };
    let mut sources = vec![format!("mirror.gcr.io/{path}")];
    // The Amazon ECR Public Gallery mirrors the official images alone.
    if path.starts_with("library/") {
        sources.push(format!("public.ecr.aws/docker/{path}"));
    }
    sources.push(image.to_owned());
    sources
}

/// `image` in the host's Docker, pulled from the first of its [`sources`] that serves it unless one is there already;
/// returns the reference it is there under.
///
/// # Errors
///
/// When no source serves it.
pub fn pulled(image: &str) -> Result<String, Failure> {
    let sources = sources(image);
    if let Some(there) = sources
        .iter()
        .find(|source| docker(&["image", "inspect", "--format", "{{.Id}}", source]).is_ok())
    {
        return Ok(there.clone());
    }
    let mut failures = Vec::new();
    for source in sources {
        match docker(&["pull", "--quiet", &source]) {
            Ok(_) => return Ok(source),
            Err(failure) => failures.push(failure.to_string()),
        }
    }
    Err(fail(&format!("pull {image}"), &failures.join("; ")))
}

/// A shell command that runs the simple command `command` makes of each of `image`'s [`sources`] in turn, until one
/// succeeds, as one group.
pub(crate) fn from_first(image: &str, command: impl Fn(&str) -> String) -> String {
    let commands: Vec<String> = sources(image)
        .iter()
        .map(|source| command(source))
        .collect();
    format!("{{ {}; }}", commands.join(" || "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_official_image_comes_from_both_mirrors_then_docker_hub() {
        assert_eq!(
            sources("docker.io/library/busybox:1.37.0@sha256:a7"),
            [
                "mirror.gcr.io/library/busybox:1.37.0@sha256:a7",
                "public.ecr.aws/docker/library/busybox:1.37.0@sha256:a7",
                "docker.io/library/busybox:1.37.0@sha256:a7",
            ]
        );
    }

    #[test]
    fn another_image_of_docker_hub_skips_the_ecr_gallery() {
        assert_eq!(
            sources("docker.io/kindest/node:v1.37.0"),
            [
                "mirror.gcr.io/kindest/node:v1.37.0",
                "docker.io/kindest/node:v1.37.0"
            ]
        );
    }

    #[test]
    fn an_image_of_another_registry_comes_from_it_alone() {
        assert_eq!(sources("ghcr.io/a/b:1"), ["ghcr.io/a/b:1"]);
    }

    #[test]
    fn the_command_falls_through_the_sources() {
        assert_eq!(
            from_first("docker.io/a/b:1", |s| format!("copy {s} x")),
            "{ copy mirror.gcr.io/a/b:1 x || copy docker.io/a/b:1 x; }"
        );
    }
}
