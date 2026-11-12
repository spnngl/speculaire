//! The pieces of Go's standard library that containerd's registry config code calls, which Rust's has no equal of.
//!
//! Ported from Go at go1.27.4 (Copyright 2009 The Go Authors, BSD-3-Clause, `NOTICE`): `net/url/url.go` (`Parse`),
//! `path/path.go` (`Clean`), `path/filepath/match.go` (`Match`, `Glob`), `time/format.go` (`ParseDuration`) and
//! `net/ipsock.go` (`SplitHostPort`). The `hosts` and `config` differential tests run them against containerd.

use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Text that Go's parser refuses.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct Refused(String);

fn refuse(message: impl Into<String>) -> Refused {
    Refused(message.into())
}

/// The parts of a URL that `hosts.toml` reads: Go's `url.Parse` result without user, query and fragment.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Url {
    pub(crate) scheme: String,
    pub(crate) host: String,
    /// Percent-decoded.
    pub(crate) path: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Host,
    Zone,
    Path,
    UserPassword,
    Fragment,
}

/// Go's `url.Parse`.
pub(crate) fn parse_url(raw: &str) -> Result<Url, Refused> {
    let (without_fragment, fragment) = match raw.split_once('#') {
        Some((url, fragment)) => (url, Some(fragment)),
        None => (raw, None),
    };
    let url = parse_without_fragment(without_fragment)?;
    if let Some(fragment) = fragment {
        unescape(fragment, Mode::Fragment)?;
    }
    Ok(url)
}

fn parse_without_fragment(raw: &str) -> Result<Url, Refused> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(refuse("invalid control character in URL"));
    }
    let mut url = Url::default();
    if raw == "*" {
        "*".clone_into(&mut url.path);
        return Ok(url);
    }
    let (scheme, rest) = get_scheme(raw)?;
    url.scheme = scheme.to_ascii_lowercase();
    let mut rest = rest;
    if rest.ends_with('?') && rest.matches('?').count() == 1 {
        rest = &rest[..rest.len() - 1];
    } else if let Some((before, _query)) = rest.split_once('?') {
        rest = before;
    }
    if !rest.starts_with('/') {
        if !url.scheme.is_empty() {
            // An opaque URL: no host, no path.
            return Ok(url);
        }
        let segment = rest.split('/').next().unwrap_or_default();
        if segment.contains(':') {
            return Err(refuse("first path segment in URL cannot contain colon"));
        }
    }
    if (!url.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let after = &rest[2..];
        let (authority, path) = after.find('/').map_or((after, ""), |i| after.split_at(i));
        url.host = parse_authority(&url.scheme, authority)?;
        rest = path;
    }
    url.path = unescape(rest, Mode::Path)?;
    Ok(url)
}

fn get_scheme(raw: &str) -> Result<(&str, &str), Refused> {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok(("", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err(refuse("missing protocol scheme"));
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

fn parse_authority(scheme: &str, authority: &str) -> Result<String, Refused> {
    let Some(at) = authority.rfind('@') else {
        return parse_host(scheme, authority);
    };
    let host = parse_host(scheme, &authority[at + 1..])?;
    let userinfo = &authority[..at];
    if !userinfo.chars().all(valid_userinfo) {
        return Err(refuse("net/url: invalid userinfo"));
    }
    match userinfo.split_once(':') {
        None => {
            unescape(userinfo, Mode::UserPassword)?;
        }
        Some((user, password)) => {
            unescape(user, Mode::UserPassword)?;
            unescape(password, Mode::UserPassword)?;
        }
    }
    Ok(host)
}

fn valid_userinfo(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._:~!$&'()*+,;=%@".contains(c)
}

fn parse_host(scheme: &str, host: &str) -> Result<String, Refused> {
    match host.rfind('[') {
        Some(0) => return parse_ip_literal(host),
        Some(_) => return Err(refuse("invalid IP-literal")),
        None => {}
    }
    if let Some(first) = host.find(':') {
        let last = host.rfind(':').unwrap_or(first);
        // Go refuses several colons in an http(s) host; GODEBUG=urlstrictcolons=0 is not set.
        let i = if scheme == "http" || scheme == "https" {
            first
        } else {
            last
        };
        let colon_port = &host[i..];
        if !valid_optional_port(colon_port) {
            return Err(refuse(format!("invalid port {colon_port:?} after host")));
        }
    }
    unescape(host, Mode::Host)
}

/// An IP-literal of RFC 3986 and RFC 6874: `[fe80::1]`, `[fe80::1%25en0]`, `[fe80::1]:80`.
fn parse_ip_literal(host: &str) -> Result<String, Refused> {
    let Some(close) = host.rfind(']') else {
        return Err(refuse("missing ']' in host"));
    };
    let colon_port = &host[close + 1..];
    if !valid_optional_port(colon_port) {
        return Err(refuse(format!("invalid port {colon_port:?} after host")));
    }
    let colon_port = unescape(colon_port, Mode::Host)?;
    let hostname = &host[1..close];
    // RFC 6874: `%25` introduces the zone, whose escapes are free within limits.
    let unescaped = match hostname.find("%25") {
        Some(zone) => {
            unescape(&hostname[..zone], Mode::Host)? + &unescape(&hostname[zone..], Mode::Zone)?
        }
        None => unescape(hostname, Mode::Host)?,
    };
    // Only an IPv6 address can be enclosed by square brackets (`netip.ParseAddr`, a zone is any non-empty text).
    let (address, zone) = match unescaped.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (unescaped.as_str(), None),
    };
    if address.parse::<Ipv6Addr>().is_err() || zone == Some("") {
        return Err(refuse("invalid host: not an IPv6 address"));
    }
    Ok(format!("[{unescaped}]{colon_port}"))
}

fn valid_optional_port(port: &str) -> bool {
    match port.strip_prefix(':') {
        None => port.is_empty(),
        Some(digits) => digits.bytes().all(|b| b.is_ascii_digit()),
    }
}

/// The bytes Go refuses in a host, as `shouldEscape(c, encodeHost)` says.
fn host_byte_refused(c: u8) -> bool {
    !(c.is_ascii_alphanumeric() || b"!$&'()*+,;=:[]<>\"".contains(&c) || b"-_.~".contains(&c))
}

fn unescape(s: &str, mode: Mode) -> Result<String, Refused> {
    let bytes = s.as_bytes();
    let hex = |b: u8| char::from(b).to_digit(16);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let digits = bytes
                    .get(i + 1)
                    .copied()
                    .and_then(hex)
                    .zip(bytes.get(i + 2).copied().and_then(hex));
                let Some((high, low)) = digits else {
                    let escape: String = s[i..].chars().take(3).collect();
                    return Err(refuse(format!("invalid URL escape {escape:?}")));
                };
                let escape = &s[i..i + 3];
                if mode == Mode::Host && high < 8 && escape != "%25" {
                    return Err(refuse(format!("invalid URL escape {escape:?}")));
                }
                let value = u8::try_from(high << 4 | low).unwrap_or_default();
                if mode == Mode::Zone
                    && escape != "%25"
                    && value != b' '
                    && host_byte_refused(value)
                {
                    return Err(refuse(format!("invalid URL escape {escape:?}")));
                }
                out.push(value);
                i += 3;
            }
            c => {
                if matches!(mode, Mode::Host | Mode::Zone) && c < 0x80 && host_byte_refused(c) {
                    return Err(refuse(format!(
                        "invalid character {:?} in host name",
                        char::from(c)
                    )));
                }
                out.push(c);
                i += 1;
            }
        }
    }
    // Go keeps the bytes of an escape that is not UTF-8; a `String` cannot.
    String::from_utf8(out).map_err(|_| refuse("URL escape decodes to invalid UTF-8"))
}

/// Go's `path.Clean`.
pub(crate) fn clean_path(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let bytes = path.as_bytes();
    let rooted = bytes[0] == b'/';
    let n = bytes.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let (mut r, mut dotdot) = (0, 0);
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }
    while r < n {
        if bytes[r] == b'/' || (bytes[r] == b'.' && (r + 1 == n || bytes[r + 1] == b'/')) {
            r += 1;
        } else if bytes[r] == b'.' && bytes[r + 1] == b'.' && (r + 2 == n || bytes[r + 2] == b'/') {
            r += 2;
            if out.len() > dotdot {
                // Drop back to the previous '/', which goes too.
                let mut dropped = out.pop();
                while out.len() > dotdot && dropped != Some(b'/') {
                    dropped = out.pop();
                }
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && bytes[r] != b'/' {
                out.push(bytes[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        return ".".to_owned();
    }
    // Only whole bytes of the input and ASCII were pushed, at the boundaries of its '/'.
    String::from_utf8(out).unwrap_or_default()
}

/// The longest duration Go's `time.ParseDuration` sums before it overflows: 2^63 ns.
const LIMIT: u64 = 1 << 63;

/// Go's `time.ParseDuration`, refusing what a [`Duration`] cannot hold: a negative duration.
pub(crate) fn parse_duration(input: &str) -> Result<Duration, Refused> {
    let invalid = || refuse(format!("time: invalid duration {input:?}"));
    let mut s = input;
    let mut negative = false;
    if let Some(rest) = s.strip_prefix(['-', '+']) {
        negative = s.starts_with('-');
        s = rest;
    }
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    if s.is_empty() {
        return Err(invalid());
    }
    let mut total: u64 = 0;
    while !s.is_empty() {
        if !(s.starts_with('.') || s.starts_with(|c: char| c.is_ascii_digit())) {
            return Err(invalid());
        }
        let (mut whole, rest) = leading_int(s).ok_or_else(invalid)?;
        let pre = rest.len() != s.len();
        s = rest;
        let (mut fraction, mut scale, mut post) = (0u64, 1f64, false);
        if let Some(rest) = s.strip_prefix('.') {
            let (f, sc, rest) = leading_fraction(rest);
            post = rest.len() != s.len() - 1;
            (fraction, scale, s) = (f, sc, rest);
        }
        if !pre && !post {
            return Err(invalid());
        }
        let unit_len = s
            .find(|c: char| c == '.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if unit_len == 0 {
            return Err(refuse(format!("time: missing unit in duration {input:?}")));
        }
        let (unit, rest) = s.split_at(unit_len);
        s = rest;
        let nanos: u64 = match unit {
            "ns" => 1,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => {
                return Err(refuse(format!(
                    "time: unknown unit {unit:?} in duration {input:?}"
                )));
            }
        };
        if whole > LIMIT / nanos {
            return Err(invalid());
        }
        whole *= nanos;
        if fraction > 0 {
            // Go truncates the float product to an integer.
            #[expect(
                clippy::cast_precision_loss,
                reason = "Go does the same sum in float64"
            )]
            let extra = fraction as f64 * (nanos as f64 / scale);
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "Go converts the same float64 to uint64"
            )]
            let extra = extra as u64;
            whole += extra;
            if whole > LIMIT {
                return Err(invalid());
            }
        }
        total += whole;
        if total > LIMIT {
            return Err(invalid());
        }
    }
    if total == 0 {
        return Ok(Duration::ZERO);
    }
    if negative {
        return Err(refuse(format!("negative duration {input:?}")));
    }
    if total > i64::MAX.unsigned_abs() {
        return Err(invalid());
    }
    Ok(Duration::from_nanos(total))
}

/// Go's `leadingInt`: the digits at the start, and the rest; `None` on overflow.
fn leading_int(s: &str) -> Option<(u64, &str)> {
    let mut x: u64 = 0;
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    for b in s[..end].bytes() {
        if x > (1 << 63) / 10 {
            return None;
        }
        x = x * 10 + u64::from(b - b'0');
        if x > 1 << 63 {
            return None;
        }
    }
    Some((x, &s[end..]))
}

/// Go's `leadingFraction`: the digits of a fraction as an integer, their scale, and the rest; digits that overflow
/// are dropped.
fn leading_fraction(s: &str) -> (u64, f64, &str) {
    let (mut x, mut scale, mut overflow) = (0u64, 1f64, false);
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    for b in s[..end].bytes() {
        if overflow {
            continue;
        }
        // Go also refuses `x > (1<<63-1)/10` first; any such `x` makes `y` exceed 1<<63 here, so one check does both.
        let y = x
            .checked_mul(10)
            .and_then(|x| x.checked_add(u64::from(b - b'0')))
            .filter(|&y| y <= 1 << 63);
        let Some(y) = y else {
            overflow = true;
            continue;
        };
        x = y;
        scale *= 10.0;
    }
    (x, scale, &s[end..])
}

/// Go's `net.SplitHostPort`, `None` where it errors.
pub(crate) fn split_host_port(hostport: &str) -> Option<(&str, &str)> {
    let i = hostport.rfind(':')?;
    let (host, j, k);
    if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        // The first ']' must come just before the last ':'. Anything else is a missing port or too many colons.
        if end + 1 != i {
            return None;
        }
        host = &hostport[1..end];
        (j, k) = (1, end + 1);
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return None;
        }
        (j, k) = (0, 0);
    }
    if hostport[j..].contains('[') || hostport[k..].contains(']') {
        return None;
    }
    Some((host, &hostport[i + 1..]))
}

/// Go's `docker.IsLocalhost`: `localhost`, or a loopback IP, with or without a port.
pub(crate) fn is_localhost(host: &str) -> bool {
    let host = split_host_port(host).map_or(host, |(host, _port)| host);
    host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

/// A pattern that Go's `filepath.Match` calls malformed.
#[derive(Debug, thiserror::Error)]
#[error("syntax error in pattern")]
pub(crate) struct BadPattern;

/// Go's `filepath.Match` on Unix.
fn matches(pattern: &str, name: &str) -> Result<bool, BadPattern> {
    let mut pattern = pattern.as_bytes();
    let mut name = name.as_bytes();
    'pattern: while !pattern.is_empty() {
        let (star, chunk, rest) = scan_chunk(pattern);
        pattern = rest;
        if star && chunk.is_empty() {
            return Ok(!name.contains(&b'/'));
        }
        let first = match_chunk(chunk, name);
        if let Ok(Some(rest_of_name)) = first
            && (rest_of_name.is_empty() || !pattern.is_empty())
        {
            name = rest_of_name;
            continue;
        }
        first?;
        if star {
            let mut i = 0;
            while i < name.len() && name[i] != b'/' {
                let attempt = match_chunk(chunk, &name[i + 1..]);
                if let Ok(Some(rest_of_name)) = attempt {
                    if pattern.is_empty() && !rest_of_name.is_empty() {
                        i += 1;
                        continue;
                    }
                    name = rest_of_name;
                    continue 'pattern;
                }
                attempt?;
                i += 1;
            }
        }
        return Ok(false);
    }
    Ok(name.is_empty())
}

fn scan_chunk(mut pattern: &[u8]) -> (bool, &[u8], &[u8]) {
    let mut star = false;
    while pattern.first() == Some(&b'*') {
        pattern = &pattern[1..];
        star = true;
    }
    let mut in_range = false;
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'\\' => {
                if i + 1 < pattern.len() {
                    i += 1;
                }
            }
            b'[' => in_range = true,
            b']' => in_range = false,
            b'*' if !in_range => break,
            _ => {}
        }
        i += 1;
    }
    (star, &pattern[..i], &pattern[i..])
}

/// A character and its length in bytes; Go's `utf8.DecodeRune`, with U+FFFD and 1 for bytes that are not UTF-8.
fn decode_rune(bytes: &[u8]) -> (char, usize) {
    for len in 1..=bytes.len().min(4) {
        if let Ok(text) = std::str::from_utf8(&bytes[..len])
            && let Some(c) = text.chars().next()
        {
            return (c, len);
        }
    }
    (char::REPLACEMENT_CHARACTER, 1)
}

fn match_chunk<'s>(mut chunk: &[u8], mut s: &'s [u8]) -> Result<Option<&'s [u8]>, BadPattern> {
    let mut failed = false;
    while !chunk.is_empty() {
        if !failed && s.is_empty() {
            failed = true;
        }
        match chunk[0] {
            b'[' => {
                let mut r = char::REPLACEMENT_CHARACTER;
                if !failed {
                    let (c, n) = decode_rune(s);
                    r = c;
                    s = &s[n..];
                }
                chunk = &chunk[1..];
                let negated = chunk.first() == Some(&b'^');
                if negated {
                    chunk = &chunk[1..];
                }
                let mut matched = false;
                let mut ranges = 0;
                loop {
                    if chunk.first() == Some(&b']') && ranges > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let (lo, rest) = get_esc(chunk)?;
                    chunk = rest;
                    let mut hi = lo;
                    if chunk.first() == Some(&b'-') {
                        let (h, rest) = get_esc(&chunk[1..])?;
                        hi = h;
                        chunk = rest;
                    }
                    if lo <= r && r <= hi {
                        matched = true;
                    }
                    ranges += 1;
                }
                if matched == negated {
                    failed = true;
                }
            }
            b'?' => {
                if !failed {
                    if s[0] == b'/' {
                        failed = true;
                    }
                    let (_, n) = decode_rune(s);
                    s = &s[n..];
                }
                chunk = &chunk[1..];
            }
            c => {
                if c == b'\\' {
                    chunk = &chunk[1..];
                    if chunk.is_empty() {
                        return Err(BadPattern);
                    }
                }
                if !failed {
                    if chunk[0] != s[0] {
                        failed = true;
                    }
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    Ok((!failed).then_some(s))
}

fn get_esc(mut chunk: &[u8]) -> Result<(char, &[u8]), BadPattern> {
    if chunk.is_empty() || chunk[0] == b'-' || chunk[0] == b']' {
        return Err(BadPattern);
    }
    if chunk[0] == b'\\' {
        chunk = &chunk[1..];
        if chunk.is_empty() {
            return Err(BadPattern);
        }
    }
    let (r, n) = decode_rune(chunk);
    if r == char::REPLACEMENT_CHARACTER && n == 1 {
        return Err(BadPattern);
    }
    let rest = &chunk[n..];
    if rest.is_empty() {
        return Err(BadPattern);
    }
    Ok((r, rest))
}

fn has_meta(path: &str) -> bool {
    path.contains(['*', '?', '[', '\\'])
}

/// Go's `filepath.Glob`: the paths that match, sorted per directory; I/O errors hide a directory.
pub(crate) fn glob(pattern: &str) -> Result<Vec<PathBuf>, BadPattern> {
    matches(pattern, "")?;
    if !has_meta(pattern) {
        return Ok(if std::fs::symlink_metadata(pattern).is_ok() {
            vec![PathBuf::from(pattern)]
        } else {
            Vec::new()
        });
    }
    let (dir, file) = pattern.split_at(pattern.rfind('/').map_or(0, |i| i + 1));
    let dir = match dir {
        "" => ".",
        "/" => "/",
        other => &other[..other.len() - 1],
    };
    if !has_meta(dir) {
        return glob_in(Path::new(dir), file);
    }
    if dir == pattern {
        return Err(BadPattern);
    }
    let mut found = Vec::new();
    for parent in glob(dir)? {
        found.extend(glob_in(&parent, file)?);
    }
    Ok(found)
}

fn glob_in(dir: &Path, pattern: &str) -> Result<Vec<PathBuf>, BadPattern> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    let mut found = Vec::new();
    for name in names {
        if matches(pattern, &name)? {
            found.push(join(dir, &name));
        }
    }
    Ok(found)
}

/// Go's `filepath.Join` of a directory and a name: `.` leaves the name alone.
fn join(dir: &Path, name: &str) -> PathBuf {
    if dir == Path::new(".") {
        PathBuf::from(name)
    } else {
        dir.join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_split_into_scheme_host_and_decoded_path() {
        let url = parse_url("HTTPS://Mirror.example:5000/v2/a%20b?x=1#frag").expect("a url");
        assert_eq!(
            url,
            Url {
                scheme: "https".to_owned(),
                host: "Mirror.example:5000".to_owned(),
                path: "/v2/a b".to_owned()
            }
        );
        assert_eq!(
            parse_url("registry.example").expect("a url").path,
            "registry.example"
        );
        assert_eq!(
            parse_url("http://[fe80::1%25eth0]:80/x")
                .expect("a url")
                .host,
            "[fe80::1%eth0]:80"
        );
    }

    #[test]
    fn urls_that_go_refuses_are_refused() {
        for bad in [
            "http://a b/",
            "http://[::1/",
            "http://[1.2.3.4]/",
            "http://a:b:80/",
            "http://a:x/",
            "http://x[a]/",
            "http://a%zz/",
            "http://a%41/",
            ":x",
            "1x:y",
            "http://[fe80::1%25]/",
        ] {
            assert!(parse_url(bad).is_err(), "{bad:?} is accepted");
        }
        assert!(parse_url("a:b").is_ok(), "an opaque URL is not refused");
    }

    #[test]
    fn paths_are_cleaned_lexically() {
        for (path, clean) in [
            ("", "."),
            ("a//b/./c/..", "a/b"),
            ("/../a", "/a"),
            ("../../a", "../../a"),
            ("/", "/"),
            ("a/..", "."),
        ] {
            assert_eq!(clean_path(path), clean, "{path:?}");
        }
    }

    #[test]
    fn durations_are_read_as_go_does() {
        for (text, seconds) in [
            ("1m30s", 90.0),
            ("1.5h", 5400.0),
            ("300ms", 0.3),
            ("0", 0.0),
            ("+2s", 2.0),
            // A fraction longer than 63 bits drops its last digits.
            ("0.12345678901234567890123456789s", 0.123_456_789),
        ] {
            let parsed = parse_duration(text).expect("a duration").as_secs_f64();
            assert!((parsed - seconds).abs() < 1e-9, "{text}: {parsed}");
        }
        for bad in ["", "1", "-1s", "1x", "s", "99999999999999999999s"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} is accepted");
        }
    }

    #[test]
    fn host_and_port_split_at_the_last_colon_outside_brackets() {
        assert_eq!(split_host_port("a.io:5000"), Some(("a.io", "5000")));
        assert_eq!(split_host_port("[::1]:80"), Some(("::1", "80")));
        assert_eq!(split_host_port("a.io"), None);
        assert_eq!(split_host_port("::1"), None);
        // A bracket anywhere else is an error, whichever of the two checks sees it.
        for bad in ["a[b:80", "a]b:80", "[a[]:80", "[a]:8]0"] {
            assert_eq!(split_host_port(bad), None, "{bad}");
        }
    }

    #[test]
    fn localhost_is_the_name_and_the_loopback_addresses() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("localhost:5000"));
        assert!(is_localhost("127.0.0.1:5000"));
        assert!(is_localhost("[::1]:5000"));
        assert!(!is_localhost("a.io"));
        assert!(!is_localhost("10.0.0.1"));
    }

    #[test]
    fn patterns_match_by_segment() {
        for (pattern, name, matched) in [
            ("*.toml", "a.toml", true),
            ("*.toml", "a/b.toml", false),
            ("a?c", "abc", true),
            ("[a-c]x", "bx", true),
            ("[^a-c]x", "bx", false),
            (r"a\*", "a*", true),
            ("*", "", true),
            // The star tries each start in the name, and a try that leaves a rest of the name is not the last.
            ("*a", "aba", true),
            ("*a", "xaab", false),
            ("*a", "xaaa", true),
            ("*/a", "x/a", true),
            ("*/a", "x/b", false),
        ] {
            assert_eq!(
                matches(pattern, name).ok(),
                Some(matched),
                "{pattern} {name}"
            );
        }
        for bad in ["[", "a[b", r"a\", "[a-]"] {
            assert!(matches(bad, "a").is_err(), "{bad:?} is accepted");
        }
    }

    #[test]
    fn globs_list_matches_in_order_and_a_missing_directory_has_none() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        for name in ["b.toml", "a.toml", "c.txt"] {
            std::fs::write(dir.path().join(name), "").expect("a file");
        }
        let pattern = format!("{}/*.toml", dir.path().display());
        let found = glob(&pattern).expect("a glob");
        let names: Vec<_> = found.iter().filter_map(|p| p.file_name()).collect();
        assert_eq!(names, ["a.toml", "b.toml"]);
        let none = glob(&format!("{}/none/*.toml", dir.path().display())).expect("a glob");
        assert_eq!(none.len(), 0);
        assert!(glob("[").is_err());
    }
}
