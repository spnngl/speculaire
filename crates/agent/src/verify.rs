//! `speculaire verify` (D156): the verdict on one image, by digest, as the agent would reach it, and each check's reason.
//! It reads the config, the policy and the trust root as the agent does, and asks upstream through the runtime's
//! registry config, never a peer, into an artifact store of its own: the agent's is the agent's alone.

use std::sync::Arc;

use anyhow::Context as _;
use speculaire_artifacts::{Discovery, Limits, Local, Store};
use speculaire_mirror::fetch::Fetcher;
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Reference;
use speculaire_runtime::Node;
use speculaire_verify::{Policies, Report, Signatures};

use crate::config::Config;
use crate::trust;

/// Verifies `image`, a name and a digest, against the policies of `config` that its name matches, over the artifacts
/// upstream serves through the registry config of `node`.
///
/// # Errors
///
/// When `image` has no digest, or the policy file, a pinned trust root or the registry config cannot be used: nothing
/// was verified. What verification cannot reach, such as upstream or a TUF trust root, is the report's.
pub fn verify(config: &Config, node: &Node, image: &str) -> anyhow::Result<Report> {
    let reference =
        Reference::parse_normalized_named(image).with_context(|| format!("the image {image}"))?;
    let digest = reference
        .digest()
        .with_context(|| {
            format!("the image {image} has no digest: name it as <name>@sha256:<hex>")
        })?
        .clone();
    let policies = Policies::load(config.verify.policy.get())?;
    let trust = trust::Source::read(&config.verify)?;
    let registries = node.registries();
    registries.reload()?;
    let name = reference.name().to_owned();
    let matched: Vec<_> = policies.matching(&reference).collect();
    if matched.is_empty() {
        return Ok(Report::unmatched(image.to_owned()));
    }
    let directory = tempfile::tempdir().context("creating an artifact store")?;
    let store = Arc::new(Store::open(directory.path()).context("opening an artifact store")?);
    let local: Arc<dyn Local> = Arc::<Store>::clone(&store);
    let max_size = config.sbom.max_size.get();
    let discovery = Discovery::new(
        Arc::clone(&store),
        local,
        // Never linked to a peer: it fetches nothing.
        Fetcher::new(
            directory.path().join("staging"),
            speculaire_mirror::space::Space::new(0),
            crate::serve::fetch_settings(config),
        ),
        registries,
        config.mirror.address.get().get().to_string(),
        Host::current(),
        Limits::new(max_size),
    );
    let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
    Ok(runtime.block_on(async {
        let root = trust.once().await;
        let artifacts = match discovery.discover(&digest, &[name]).await {
            Ok(artifacts) => artifacts,
            Err(e) => return Report::undiscovered(image.to_owned(), &matched, &e),
        };
        let signatures = Signatures::new(max_size);
        Report::check(
            image.to_owned(),
            &signatures,
            &store,
            &digest,
            &artifacts,
            &matched,
            root.as_deref(),
        )
        .await
    }))
}
