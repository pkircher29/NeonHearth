use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 256;
const MAX_DEPTH: usize = 16;
const MAX_KEYS: usize = 128;

pub fn record(input: &[u8], fingerprint: &str, authorized: bool) -> Result<Vec<u8>> {
    if !authorized {
        bail!("refusing: --owner-authorized-home-router is required");
    }
    if input.len() > MAX_INPUT {
        bail!("input exceeds safety limit");
    }
    if fingerprint.is_empty()
        || fingerprint.len() > 256
        || !fingerprint
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        bail!("invalid firmware/profile fingerprint");
    }
    let har: Value = serde_json::from_slice(input).context("invalid trace JSON")?;
    let entries = har
        .get("log")
        .and_then(|v| v.get("entries"))
        .and_then(Value::as_array)
        .context("trace must contain log.entries")?;
    if entries.len() > MAX_ENTRIES {
        bail!("trace has too many entries");
    }
    let mut out = Vec::new();
    for e in entries {
        out.push(sanitize_entry(e)?);
    }
    serde_json::to_vec_pretty(&json!({"schema":"w6-compat-fixture-v1","fingerprint": fingerprint_hash(fingerprint),"entries":out})).map_err(Into::into)
}

fn fingerprint_hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("sha256:{:x}", h.finalize())
}
fn sanitize_entry(e: &Value) -> Result<Value> {
    let req = e.get("request").context("entry missing request")?;
    let res = e.get("response").context("entry missing response")?;
    let method = req.get("method").and_then(Value::as_str).unwrap_or("GET");
    let url = req
        .get("url")
        .and_then(Value::as_str)
        .context("request missing url")?;
    let path = normalized_path(url);
    let status = res.get("status").and_then(Value::as_u64).unwrap_or(0);
    let ct = res
        .get("content")
        .and_then(|v| v.get("mimeType"))
        .and_then(Value::as_str)
        .map(safe_content_type)
        .unwrap_or("unknown");
    let shape = res
        .get("content")
        .and_then(|v| v.get("text"))
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
        .map(|v| shape(&v, 0))
        .unwrap_or(Value::Null);
    Ok(
        json!({"method":method,"path":path,"status":status,"content_type":ct,"response_shape":shape}),
    )
}
fn normalized_path(url: &str) -> String {
    let p = url
        .split_once("//")
        .and_then(|(_, x)| x.split_once('/').map(|(_, p)| p))
        .unwrap_or(url);
    let p = p
        .split('?')
        .next()
        .unwrap_or(p)
        .split('#')
        .next()
        .unwrap_or(p);
    let seg: Vec<_> = p
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
                && s.len() <= 24
                && [
                    "api", "v1", "status", "config", "info", "health", "wifi", "network",
                ]
                .contains(&s)
            {
                s
            } else {
                ":param"
            }
        })
        .collect();
    format!("/{}", seg.join("/"))
}
fn safe_content_type(s: &str) -> &str {
    if s.eq_ignore_ascii_case("application/json") {
        "application/json"
    } else if s.to_ascii_lowercase().starts_with("text/") {
        "text/plain"
    } else {
        "other"
    }
}
fn shape(v: &Value, depth: usize) -> Value {
    if depth >= MAX_DEPTH {
        return json!("depth");
    }
    match v {
        Value::Object(m) => {
            let mut o = Map::new();
            for (k, v) in m.iter().take(MAX_KEYS) {
                if sensitive(k) {
                    continue;
                }
                o.insert(k.clone(), shape(v, depth + 1));
            }
            json!({"object":o})
        }
        Value::Array(a) => {
            json!({"array":a.iter().take(MAX_KEYS).map(|v|shape(v,depth+1)).collect::<Vec<_>>() })
        }
        Value::String(_) => json!("string"),
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("boolean"),
        Value::Null => json!("null"),
    }
}
fn sensitive(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    [
        "authorization",
        "cookie",
        "set-cookie",
        "csrf",
        "token",
        "password",
        "username",
        "secret",
    ]
    .iter()
    .any(|x| k.contains(x))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_owner_authorization() {
        assert!(
            record(b"{}", "fw", false)
                .unwrap_err()
                .to_string()
                .contains("required")
        );
    }
    #[test]
    fn sanitizes_canaries_deterministically() {
        let h=br#"{"log":{"entries":[{"request":{"method":"GET","url":"http://192.168.1.8/api/status?password=CANARY","headers":[{"name":"Authorization","value":"CANARY"}]},"response":{"status":200,"content":{"mimeType":"application/json","text":"{\"serial\":\"CANARY\",\"ok\":true}"}}}]}}"#;
        let a = record(h, "firmware-x", true).unwrap();
        assert_eq!(a, record(h, "firmware-x", true).unwrap());
        let s = String::from_utf8(a).unwrap();
        assert!(!s.contains("CANARY"));
        assert!(!s.contains("192.168.1.8"));
    }
}
