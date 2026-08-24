use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const MAX_INPUT: usize = 16 * 1024 * 1024;
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
    let baseline = entries.iter().filter_map(entry_time).min();
    for e in entries {
        out.push(sanitize_entry(e, baseline)?);
    }
    serde_json::to_vec_pretty(&json!({"schema":"w6-compat-fixture-v1","fingerprint": fingerprint_hash(fingerprint),"entries":out})).map_err(Into::into)
}

fn fingerprint_hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("sha256:{:x}", h.finalize())
}
fn sanitize_entry(e: &Value, baseline: Option<DateTime<Utc>>) -> Result<Value> {
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
    let relative_start_ms = entry_time(e)
        .zip(baseline)
        .map(|(time, baseline)| (time - baseline).num_milliseconds().max(0))
        .unwrap_or(0);
    Ok(
        json!({"method":method,"path":path,"status":status,"content_type":ct,"relative_start_ms":relative_start_ms,"response_shape":shape}),
    )
}
fn entry_time(e: &Value) -> Option<DateTime<Utc>> {
    e.get("startedDateTime")?.as_str()?.parse().ok()
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
        "device_name",
        "serial_number",
        "mac_address",
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

    #[test]
    fn preserves_relative_entry_timing_without_absolute_dates() {
        let h = br#"{"log":{"entries":[
          {"startedDateTime":"2026-01-01T00:00:01.000Z","request":{"url":"http://router/api/status"},"response":{}},
          {"startedDateTime":"2026-01-01T00:00:01.250Z","request":{"url":"http://router/api/info"},"response":{}}
        ]}}"#;
        let output = String::from_utf8(record(h, "fw", true).unwrap()).unwrap();
        assert!(output.contains("\"relative_start_ms\": 0"));
        assert!(output.contains("\"relative_start_ms\": 250"));
        assert!(!output.contains("2026-01-01"));
    }

    #[test]
    fn removes_structural_identity_keys() {
        let h = br#"{"log":{"entries":[{"request":{"url":"http://router/api/status"},"response":{"content":{"text":"{\"device_name\":\"CANARY\",\"serial_number\":\"CANARY\",\"mac_address\":\"CANARY\",\"safe\":true}"}}}]}}"#;
        let output = String::from_utf8(record(h, "fw", true).unwrap()).unwrap();
        assert!(!output.contains("device_name"));
        assert!(!output.contains("serial_number"));
        assert!(!output.contains("mac_address"));
        assert!(output.contains("safe"));
    }
}
