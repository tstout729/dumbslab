use chrono::{DateTime, Duration, SecondsFormat, Utc};
use hmac::{KeyInit, Mac};
use rand::RngExt;
use sha2::{Digest, Sha256};

const ID_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const TOKEN_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn random_string(alphabet: &[u8], len: usize) -> String {
    let mut rng = rand::rng();
    (0..len).map(|_| alphabet[rng.random_range(0..alphabet.len())] as char).collect()
}

/// Random bytes, e.g. for a nonce.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill(&mut out);
    out
}

/// A short, URL-friendly random id, e.g. `k3v9q0x2mz`.
pub fn new_id() -> String {
    random_string(ID_ALPHABET, 10)
}

/// A high-entropy secret (about 190 bits).
pub fn new_secret(prefix: &str) -> String {
    format!("{prefix}{}", random_string(TOKEN_ALPHABET, 32))
}

pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

pub fn hmac_sha256_hex(key: &str, message: &str) -> String {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time string comparison for secrets.
pub fn secure_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

pub fn ts_plus(now: DateTime<Utc>, d: Duration) -> String {
    ts(now + d)
}

/// `"Getting Started: Ops 101"` → `"getting-started-ops-101"`.
pub fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars().flat_map(|c| c.to_lowercase()) {
        if c.is_alphanumeric() {
            out.push(c);
            dash = false;
        } else if !out.is_empty() && !dash {
            out.push('-');
            dash = true;
        }
        if out.len() >= 80 {
            break;
        }
    }
    let trimmed = out.trim_end_matches('-').to_string();
    if trimmed.is_empty() { "untitled".into() } else { trimmed }
}

/// Lowercase handle made of letters, digits, `_`, `.` and `-`.
pub fn normalize_handle(s: &str) -> String {
    let h: String = s
        .trim()
        .trim_start_matches('@')
        .chars()
        .flat_map(|c| c.to_lowercase())
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' { c } else { '-' })
        .collect();
    h.trim_matches(|c| c == '-' || c == '.').chars().take(32).collect()
}

pub fn is_valid_email(s: &str) -> bool {
    let s = s.trim();
    match s.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !s.contains(' ') && s.len() <= 254
        }
        None => false,
    }
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert_eq!(slugify("Getting Started: Ops 101"), "getting-started-ops-101");
        assert_eq!(slugify("  --  "), "untitled");
        assert_eq!(slugify("Café déjà vu"), "café-déjà-vu");
    }

    #[test]
    fn handles() {
        assert_eq!(normalize_handle("@Trevor Stout"), "trevor-stout");
        assert_eq!(normalize_handle("ops.bot_1"), "ops.bot_1");
    }

    #[test]
    fn ids_are_unique_and_short() {
        let a = new_id();
        assert_eq!(a.len(), 10);
        assert_ne!(a, new_id());
        assert!(new_secret("ds_pat_").starts_with("ds_pat_"));
    }

    #[test]
    fn secure_eq_works() {
        assert!(secure_eq("abc", "abc"));
        assert!(!secure_eq("abc", "abd"));
        assert!(!secure_eq("abc", "abcd"));
    }
}
