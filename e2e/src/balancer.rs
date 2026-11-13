//! The reflectors' load balancer (D2, D94). `just e2e-up` starts it as `<cluster>-lb`: Envoy, passing TCP through on
//! port 7483 to `reflector.listen` of [`Cluster::reflectors`], round robin, with a TCP health check every second.
//! Every agent's `reflector.url` names its address.

use std::net::IpAddr;

use crate::registry::{NETWORK, docker, fail};
use crate::{Cluster, Failure, IpFamily};

/// The port of the balancer and of `reflector.listen`.
pub const PORT: u16 = 7483;

/// The balancer; `just e2e-up` starts it and `just e2e-down` removes it.
pub struct Balancer<'a> {
    cluster: &'a Cluster,
}

impl Cluster {
    /// The reflectors' load balancer.
    #[must_use]
    pub fn balancer(&self) -> Balancer<'_> {
        Balancer { cluster: self }
    }
}

impl Balancer<'_> {
    /// Its address on kind's network, IPv6 on a dual-stack cluster, as `reflector.url` names it.
    ///
    /// # Errors
    ///
    /// When `docker inspect` fails or prints no address.
    pub fn address(&self) -> Result<IpAddr, Failure> {
        let field = match self.cluster.family {
            IpFamily::Ipv4 => "IPAddress",
            IpFamily::Dual => "GlobalIPv6Address",
        };
        let name = format!("{}-lb", self.cluster.name);
        let out = docker(&[
            "inspect",
            "-f",
            &format!("{{{{(index .NetworkSettings.Networks \"{NETWORK}\").{field}}}}}"),
            &name,
        ])?;
        out.trim()
            .parse()
            .map_err(|e| fail(&format!("docker inspect {name}"), &format!("{out:?}: {e}")))
    }

    /// What Envoy logged, for a failing test to show.
    ///
    /// # Errors
    ///
    /// When `docker logs` fails.
    pub fn logs(&self) -> Result<String, Failure> {
        // Envoy logs to stderr.
        let script = format!("docker logs --tail 40 {}-lb 2>&1", self.cluster.name);
        crate::run(std::process::Command::new("sh").args(["-c", &script]))
    }

    /// Cuts the balancer off from the reflector of `node`, until the guard drops: the node resets its connections,
    /// so the health check fails and the balancer sends the next ones to the other reflector.
    ///
    /// # Errors
    ///
    /// When `iptables` fails.
    pub fn stop(&self, node: &str) -> Result<Stopped<'_>, Failure> {
        let address = self.address()?;
        let tables = if address.is_ipv6() {
            "ip6tables"
        } else {
            "iptables"
        };
        let rule =
            format!("INPUT -s {address} -p tcp --dport {PORT} -j REJECT --reject-with tcp-reset");
        let stopped = Stopped {
            cluster: self.cluster,
            node: node.to_owned(),
            iptables: format!("{tables} -w"),
            rule,
        };
        stopped.iptables("-C").or_else(|_| stopped.iptables("-I"))?;
        Ok(stopped)
    }
}

/// A reflector the balancer cannot reach; it can again when this drops.
pub struct Stopped<'a> {
    cluster: &'a Cluster,
    node: String,
    iptables: String,
    rule: String,
}

impl Stopped<'_> {
    /// Checks (`-C`), inserts (`-I`) or deletes (`-D`) the rule.
    fn iptables(&self, command: &str) -> Result<String, Failure> {
        self.cluster.exec(
            &self.node,
            &[
                "sh",
                "-c",
                &format!("{} {command} {}", self.iptables, self.rule),
            ],
        )
    }
}

impl Drop for Stopped<'_> {
    fn drop(&mut self) {
        let _ = self.iptables("-D");
    }
}
