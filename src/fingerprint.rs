use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cookie::Cookie;
use hmac::{Hmac, Mac};
use hyper::{header::HeaderValue, Body, HeaderMap, Request, Response};
use log::warn;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
	collections::HashSet,
	sync::{LazyLock, RwLock},
};
use time::{Duration, OffsetDateTime};

use crate::{client::CLIENT, config, server::RequestExt};

type HmacSha256 = Hmac<Sha256>;

const FP_COOKIE_NAME: &str = "yay";
const FP_GATE_COOKIE_NAME: &str = "eris";
const FP_VERSION: u8 = 1;
const FP_TOKEN_LEN: usize = 1 + 8 + 16 + 8 + 32;

const UA_CHROME_WINDOW_MAJORS: u32 = 10;
const UA_VERSION_SLACK_MAJORS: u32 = 1;
const IOS_CURRENT_MAJOR: u32 = 26;
const UA_REFRESH_SECONDS: i64 = 6 * 60 * 60;

const FP_GATE_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex,nofollow,noarchive,nosnippet">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title></title>
    <style>html,body{margin:0;padding:0;background:#fff}</style>
    <script src="/__aqua/yurification.js" defer></script>
  </head>
  <body></body>
</html>
"#;

#[derive(Debug, Deserialize)]
struct FingerprintReport {
	#[serde(default)]
	v: u8,
	#[serde(default)]
	webdriver: Option<bool>,
	#[serde(default)]
	max_touch_points: Option<u16>,
	#[serde(default)]
	touch_event: Option<bool>,
	#[serde(default)]
	platform: Option<String>,
	#[serde(default)]
	tz: Option<String>,
	#[serde(default)]
	langs: Option<Vec<String>>,
	#[serde(default)]
	canvas: Option<String>,
	#[serde(default)]
	webgl_vendor: Option<String>,
	#[serde(default)]
	webgl_renderer: Option<String>,
	#[serde(default)]
	hardware_concurrency: Option<u16>,
	#[serde(default)]
	device_memory: Option<f32>,
	#[serde(default)]
	screen_w: Option<u32>,
	#[serde(default)]
	screen_h: Option<u32>,
	#[serde(default)]
	dpr: Option<f32>,
	#[serde(default)]
	plugins: Option<u16>,
}

struct FingerprintSettings {
	enabled: bool,
	secret: Vec<u8>,
	max_age_seconds: i64,
	score_threshold: u32,
	blocklist: HashSet<[u8; 16]>,
}

static FP_SETTINGS: LazyLock<FingerprintSettings> = LazyLock::new(load_settings);

#[derive(Clone, Copy, Debug, Default)]
struct UaVersionState {
	last_refresh_unix: i64,
	chrome_stable_major: Option<u32>,
}

static UA_VERSIONS: LazyLock<RwLock<UaVersionState>> = LazyLock::new(|| RwLock::new(UaVersionState::default()));

fn load_settings() -> FingerprintSettings {
	let enabled = matches!(config::get_setting("REDLIB_FINGERPRINTING"), Some(v) if v == "on");
	let max_age_seconds = config::get_setting("REDLIB_FINGERPRINT_MAX_AGE_SECONDS")
		.and_then(|v| v.parse::<i64>().ok())
		.filter(|v| *v > 0 && *v <= 60 * 60 * 24 * 30)
		.unwrap_or(60 * 60 * 24);

	let score_threshold = config::get_setting("REDLIB_FINGERPRINT_SCORE_THRESHOLD")
		.and_then(|v| v.parse::<u32>().ok())
		.filter(|v| *v > 0 && *v <= 10_000)
		.unwrap_or(50);

	let secret = config::get_setting("REDLIB_FINGERPRINT_SECRET")
		.filter(|v| !v.is_empty())
		.map(|v| v.into_bytes())
		.unwrap_or_else(|| {
			if enabled {
				warn!("REDLIB_FINGERPRINTING is enabled but REDLIB_FINGERPRINT_SECRET is unset; using an ephemeral in-memory secret (cookies will break on restart).");
			}
			let mut s = [0u8; 32];
			fastrand::fill(&mut s);
			s.to_vec()
		});

	let blocklist = config::get_setting("REDLIB_FINGERPRINT_BLOCKLIST")
		.unwrap_or_default()
		.split(',')
		.map(str::trim)
		.filter(|s| !s.is_empty())
		.filter_map(parse_fp_id_hex)
		.collect::<HashSet<_>>();

	FingerprintSettings {
		enabled,
		secret,
		max_age_seconds,
		score_threshold,
		blocklist,
	}
}

pub fn enabled() -> bool {
	FP_SETTINGS.enabled
}

pub fn is_fingerprint_path(path: &str) -> bool {
	path == "/__aqua/axis_order" || path == "/__aqua/yurification.js"
}

pub fn start_ua_versions_daemon() {
	if !enabled() {
		return;
	}

	let Ok(handle) = tokio::runtime::Handle::try_current() else {
		return;
	};

	handle.spawn(async move {
		// Best-effort: keep cached versions reasonably fresh, never fail hard.
		loop {
			let _ = refresh_ua_versions_once().await;
			tokio::time::sleep(std::time::Duration::from_secs(UA_REFRESH_SECONDS.max(60) as u64)).await;
		}
	});
}

pub fn is_suspicious_headers(headers: &HeaderMap<HeaderValue>) -> bool {
	let ua = header_str(headers, "user-agent").unwrap_or_default();
	if ua.is_empty() {
		return true;
	}

	let ua_lc = ua.to_ascii_lowercase();
	// Block Internet Explorer and legacy IE mobile outright.
	if ua_lc.contains("msie") || ua_lc.contains("trident/") || ua_lc.contains("iemobile") {
		return true;
	}
	let non_browser = [
		"curl/", "wget/", "python-requests", "go-http-client", "httpie/", "postmanruntime/", "libwww-perl", "java/", "okhttp", "scrapy",
	];
	if non_browser.iter().any(|p| ua_lc.contains(p)) {
		return true;
	}

	// A very common signature of non-browser traffic.
	let has_accept = headers.get("accept").is_some();
	let has_accept_lang = headers.get("accept-language").is_some();
	if (!has_accept) && (!has_accept_lang) {
		return true;
	}

	// UA age gating: reject browsers that look too old.
	if ua_is_too_old(&ua) {
		return true;
	}

	false
}

pub fn verify_cookie(req: &Request<Body>) -> bool {
	let token = match req.cookie(FP_COOKIE_NAME) {
		Some(c) => c.value().to_string(),
		None => return false,
	};

	let ua = header_str(req.headers(), "user-agent").unwrap_or_default();
	let ua_hash = ua_hash8(ua.as_bytes());

	let decoded = match URL_SAFE_NO_PAD.decode(token.as_bytes()) {
		Ok(b) => b,
		Err(_) => return false,
	};
	if decoded.len() != FP_TOKEN_LEN {
		return false;
	}

	if decoded[0] != FP_VERSION {
		return false;
	}

	let ts = u64::from_be_bytes(decoded[1..9].try_into().unwrap_or_default()) as i64;
	let now = OffsetDateTime::now_utc().unix_timestamp();
	if ts <= 0 || now - ts > FP_SETTINGS.max_age_seconds {
		return false;
	}

	let fp_id: [u8; 16] = decoded[9..25].try_into().unwrap_or_default();
	if FP_SETTINGS.blocklist.contains(&fp_id) {
		return false;
	}

	let token_ua_hash: [u8; 8] = decoded[25..33].try_into().unwrap_or_default();
	if token_ua_hash != ua_hash {
		return false;
	}

	let data = &decoded[..(1 + 8 + 16 + 8)];
	let sig = &decoded[(1 + 8 + 16 + 8)..];
	let mut mac = match HmacSha256::new_from_slice(&FP_SETTINGS.secret) {
		Ok(m) => m,
		Err(_) => return false,
	};
	mac.update(data);
	mac.verify_slice(sig).is_ok()
}

pub fn gate_cookie_present(req: &Request<Body>) -> bool {
	req.cookie(FP_GATE_COOKIE_NAME).is_some()
}

pub fn blank_response() -> Response<Body> {
	Response::builder()
		.status(200)
		.header("cache-control", "no-store")
		.body(Body::empty())
		.unwrap_or_default()
}

pub fn gate_page_response(headers: &HeaderMap<HeaderValue>) -> Response<Body> {
	let mut res = Response::builder()
		.status(200)
		.header("content-type", "text/html; charset=utf-8")
		.header("cache-control", "no-store")
		.body(Body::from(FP_GATE_HTML))
		.unwrap_or_default();

	// Mark that the gate was served once. If the browser can't run/load JS,
	// subsequent requests will stay blank without repeatedly serving HTML.
	let now = OffsetDateTime::now_utc();
	let mut gate_cookie = Cookie::build((FP_GATE_COOKIE_NAME, "pads_her_chest"))
		.path("/")
		.http_only(true)
		.expires(now + Duration::minutes(10));
	if is_https(headers) {
		gate_cookie = gate_cookie.secure(true);
	}
	if let Ok(val) = HeaderValue::from_str(&gate_cookie.to_string()) {
		res.headers_mut().append("set-cookie", val);
	}

	// Ensure intermediaries don't cache the gate response and replay it to verified users.
	if let Ok(val) = HeaderValue::from_str("no-cache") {
		res.headers_mut().insert("pragma", val);
	}
	res
}

pub async fn script(req: Request<Body>) -> Result<Response<Body>, String> {
	// Don't expose the fingerprint script to obvious non-browser clients.
	if is_suspicious_headers(req.headers()) {
		return Ok(blank_response());
	}

	Ok(
		Response::builder()
			.status(200)
			.header("content-type", "text/javascript; charset=utf-8")
			.header("cache-control", "no-store")
			.body(Body::from(include_str!("../static/fingerprint.js")))
			.unwrap_or_default(),
	)
}

pub async fn verify(req: Request<Body>) -> Result<Response<Body>, String> {
	if !enabled() {
		return Ok(json_ok(true, None));
	}

	let headers = req.headers().clone();
	let ua = header_str(&headers, "user-agent").unwrap_or_default();

	let body = hyper::body::to_bytes(req.into_body())
		.await
		.map_err(|e| format!("Failed to read request body: {e}"))?;
	if body.len() > 16 * 1024 {
		return Ok(json_ok(false, None));
	}

	let report: FingerprintReport = match serde_json::from_slice(&body) {
		Ok(v) => v,
		Err(_) => return Ok(json_ok(false, None)),
	};

	if report.v != FP_VERSION {
		return Ok(json_ok(false, None));
	}

	let (ok, fp_id) = evaluate(&report, &headers, ua.as_bytes());
	if !ok {
		return Ok(json_ok(false, Some(fp_id)));
	}

	let now = OffsetDateTime::now_utc();
	let token = issue_token(now.unix_timestamp(), fp_id, ua_hash8(ua.as_bytes()));
	let mut cookie =
		Cookie::build((FP_COOKIE_NAME, token)).path("/").http_only(true).expires(now + Duration::seconds(FP_SETTINGS.max_age_seconds));

	// If we can confidently infer HTTPS, mark the cookie as secure.
	// This is best-effort because Redlib often runs behind a reverse proxy.
	if is_https(&headers) {
		cookie = cookie.secure(true);
	}

	let mut res = json_ok(true, Some(fp_id));
	if let Ok(val) = HeaderValue::from_str(&cookie.to_string()) {
		res.headers_mut().append("set-cookie", val);
	}
	Ok(res)
}

async fn refresh_ua_versions_once() -> Result<(), String> {
	let now = OffsetDateTime::now_utc().unix_timestamp();
	{
		let state = UA_VERSIONS.read().map_err(|_| "UA_VERSIONS poisoned".to_string())?;
		if state.last_refresh_unix > 0 && now - state.last_refresh_unix < UA_REFRESH_SECONDS {
			return Ok(());
		}
	}

	let chrome = fetch_chrome_stable_major().await;

	let mut state = UA_VERSIONS.write().map_err(|_| "UA_VERSIONS poisoned".to_string())?;
	state.last_refresh_unix = now;
	if let Ok(v) = chrome {
		state.chrome_stable_major = Some(v);
	}

	Ok(())
}

async fn fetch_chrome_stable_major() -> Result<u32, String> {
	// Official Google VersionHistory API.
	// Default ordering is newest first; pageSize=1 keeps payload small.
	let uri: hyper::Uri = "https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions?pageSize=1"
		.parse()
		.map_err(|e| format!("Invalid Chrome VersionHistory URI: {e}"))?;

	let resp = CLIENT.get(uri).await.map_err(|e| format!("Failed to fetch Chrome version: {e}"))?;
	let bytes = hyper::body::to_bytes(resp.into_body())
		.await
		.map_err(|e| format!("Failed to read Chrome version body: {e}"))?;

	let json: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| format!("Failed to parse Chrome version JSON: {e}"))?;
	let version = json["versions"][0]["version"].as_str().ok_or_else(|| "Missing Chrome version".to_string())?;
	let major = version.split('.').next().and_then(|v| v.parse::<u32>().ok()).ok_or_else(|| "Bad Chrome version".to_string())?;
	Ok(major)
}

fn ua_is_too_old(ua: &str) -> bool {
	let ua_lc = ua.to_ascii_lowercase();

	if let Some(major) = parse_chrome_family_major(&ua_lc) {
		let current = UA_VERSIONS.read().ok().and_then(|s| s.chrome_stable_major);
		let Some(current) = current else { return false };
		let min_allowed = current.saturating_sub(UA_CHROME_WINDOW_MAJORS + UA_VERSION_SLACK_MAJORS);
		return major < min_allowed;
	}

	// iOS gating: hardcode current iOS major (Safari check alone is unreliable).
	// Apply this to all iOS browsers (Safari/Chrome/Edge/etc.) based on the `OS {major}_...` UA segment.
	if ua_lc.contains("iphone") || ua_lc.contains("ipad") || ua_lc.contains("ipod") {
		if let Some(major) = parse_ios_os_major(&ua_lc) {
			return major < IOS_CURRENT_MAJOR;
		}
		// If it claims to be iOS but we can't parse the OS major, treat it as suspicious.
		return true;
	}

	false
}

fn parse_chrome_family_major(ua_lc: &str) -> Option<u32> {
	// Prefer explicit tokens where present; fall back to Chrome/ for most Chromium browsers.
	for token in ["edg/", "edgios/", "crios/", "opr/", "chrome/"] {
		if let Some(v) = parse_major_after(ua_lc, token) {
			return Some(v);
		}
	}
	None
}

fn parse_ios_os_major(ua_lc: &str) -> Option<u32> {
	// iOS UA segment: "OS 26_2 like Mac OS X"
	let idx = ua_lc.find("os ")?;
	let tail = &ua_lc[idx + 3..];
	let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
	digits.parse::<u32>().ok()
}

fn parse_major_after(ua_lc: &str, needle: &str) -> Option<u32> {
	let idx = ua_lc.find(needle)?;
	let tail = &ua_lc[idx + needle.len()..];
	let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
	digits.parse::<u32>().ok()
}

fn json_ok(ok: bool, fp_id: Option<[u8; 16]>) -> Response<Body> {
	let fp_hex = fp_id.map(|id| hex_lower(&id));
	let body = match fp_hex {
		Some(id) => format!(r#"{{"ok":{},"fp":"{}"}}"#, if ok { "true" } else { "false" }, id),
		None => format!(r#"{{"ok":{}}}"#, if ok { "true" } else { "false" }),
	};

	Response::builder()
		.status(200)
		.header("content-type", "application/json; charset=utf-8")
		.header("cache-control", "no-store")
		.body(Body::from(body))
		.unwrap_or_default()
}

fn evaluate(report: &FingerprintReport, headers: &HeaderMap<HeaderValue>, ua_bytes: &[u8]) -> (bool, [u8; 16]) {
	let fp_id = fingerprint_id(report);
	if FP_SETTINGS.blocklist.contains(&fp_id) {
		return (false, fp_id);
	}

	let mut score: u32 = 0;

	// Strong bot / automation signals.
	if report.webdriver == Some(true) {
		score += 10_000;
	}
	let ua = String::from_utf8_lossy(ua_bytes).to_ascii_lowercase();
	if ua.contains("headlesschrome") || ua.contains("phantomjs") || ua.contains("selenium") {
		score += 10_000;
	}

	// Suspicious headers (curl, etc).
	if is_suspicious_headers(headers) {
		score += 1_000;
	}

	// Feature mismatch: mobile UA but no touch.
	let is_mobile_ua = ua.contains("iphone") || ua.contains("ipad") || ua.contains("android");
	let has_touch = report.max_touch_points.unwrap_or(0) > 0 || report.touch_event.unwrap_or(false);
	if is_mobile_ua && !has_touch {
		score += 250;
	}

	// Missing / blocked APIs.
	if report.canvas.as_deref().unwrap_or_default().is_empty() {
		score += 50;
	}
	if report.webgl_renderer.as_deref().unwrap_or_default().is_empty() {
		score += 25;
	}
	if report.tz.as_deref().unwrap_or_default().is_empty() {
		score += 10;
	}
	if report.langs.as_ref().map(|l| l.is_empty()).unwrap_or(true) {
		score += 10;
	}

	// Unusual "too-empty" browser environment.
	if report.plugins == Some(0) {
		score += 25;
	}
	if report.screen_w.unwrap_or(0) == 0 || report.screen_h.unwrap_or(0) == 0 {
		score += 25;
	}
	if report.dpr.unwrap_or(0.0) <= 0.0 {
		score += 25;
	}

	(score < FP_SETTINGS.score_threshold, fp_id)
}

fn fingerprint_id(report: &FingerprintReport) -> [u8; 16] {
	let mut input = Vec::with_capacity(512);

	input.extend_from_slice(b"v1\0");
	push_opt(&mut input, report.canvas.as_deref());
	push_opt(&mut input, report.webgl_vendor.as_deref());
	push_opt(&mut input, report.webgl_renderer.as_deref());
	push_opt(&mut input, report.platform.as_deref());
	push_opt(&mut input, report.tz.as_deref());

	if let Some(langs) = &report.langs {
		for l in langs {
			input.extend_from_slice(l.as_bytes());
			input.push(0);
		}
	} else {
		input.push(0);
	}

	push_opt(&mut input, report.hardware_concurrency.map(|v| v.to_string()).as_deref());
	push_opt(&mut input, report.device_memory.map(|v| v.to_string()).as_deref());
	push_opt(&mut input, report.screen_w.map(|v| v.to_string()).as_deref());
	push_opt(&mut input, report.screen_h.map(|v| v.to_string()).as_deref());
	push_opt(&mut input, report.dpr.map(|v| v.to_string()).as_deref());
	push_opt(&mut input, report.plugins.map(|v| v.to_string()).as_deref());

	let digest = Sha256::digest(&input);
	let mut out = [0u8; 16];
	out.copy_from_slice(&digest[..16]);
	out
}

fn push_opt(buf: &mut Vec<u8>, s: Option<&str>) {
	if let Some(v) = s {
		buf.extend_from_slice(v.as_bytes());
	}
	buf.push(0);
}

fn issue_token(ts: i64, fp_id: [u8; 16], ua_hash: [u8; 8]) -> String {
	let ts_u64 = ts.max(0) as u64;

	let mut data = [0u8; 1 + 8 + 16 + 8];
	data[0] = FP_VERSION;
	data[1..9].copy_from_slice(&ts_u64.to_be_bytes());
	data[9..25].copy_from_slice(&fp_id);
	data[25..33].copy_from_slice(&ua_hash);

	let mut mac = HmacSha256::new_from_slice(&FP_SETTINGS.secret).expect("HMAC can always be initialized with a byte slice");
	mac.update(&data);
	let sig = mac.finalize().into_bytes();

	let mut token = Vec::with_capacity(FP_TOKEN_LEN);
	token.extend_from_slice(&data);
	token.extend_from_slice(&sig);

	URL_SAFE_NO_PAD.encode(token)
}

fn ua_hash8(ua: &[u8]) -> [u8; 8] {
	let digest = Sha256::digest(ua);
	let mut out = [0u8; 8];
	out.copy_from_slice(&digest[..8]);
	out
}

fn parse_fp_id_hex(s: &str) -> Option<[u8; 16]> {
	let s = s.trim();
	if s.len() != 32 {
		return None;
	}

	let mut out = [0u8; 16];
	for (i, slot) in out.iter_mut().enumerate() {
		let hi = hex_val(s.as_bytes()[i * 2])?;
		let lo = hex_val(s.as_bytes()[i * 2 + 1])?;
		*slot = (hi << 4) | lo;
	}
	Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}

fn hex_lower(bytes: &[u8]) -> String {
	const LUT: &[u8; 16] = b"0123456789abcdef";
	let mut out = Vec::with_capacity(bytes.len() * 2);
	for &b in bytes {
		out.push(LUT[(b >> 4) as usize]);
		out.push(LUT[(b & 0x0f) as usize]);
	}
	String::from_utf8(out).unwrap_or_default()
}

fn header_str(headers: &HeaderMap<HeaderValue>, name: &str) -> Option<String> {
	headers.get(name).and_then(|h| h.to_str().ok()).map(|s| s.to_string())
}

fn is_https(headers: &HeaderMap<HeaderValue>) -> bool {
	// Best-effort: common reverse proxy header.
	if let Some(proto) = headers.get("x-forwarded-proto").and_then(|h| h.to_str().ok()) {
		return proto.eq_ignore_ascii_case("https");
	}
	false
}

#[cfg(test)]
mod tests {
	use super::*;
	use hyper::header::HeaderMap;

	#[test]
	fn fp_id_hex_roundtrip() {
		let id = [0xabu8; 16];
		let hex = hex_lower(&id);
		assert_eq!(parse_fp_id_hex(&hex), Some(id));
	}

	#[test]
	fn token_roundtrip() {
		let fp_id = [0x11u8; 16];
		let ua_hash = [0x22u8; 8];
		let ts = OffsetDateTime::now_utc().unix_timestamp();

		// Force deterministic secret for this test.
		let token = {
			let mut data = [0u8; 1 + 8 + 16 + 8];
			data[0] = FP_VERSION;
			data[1..9].copy_from_slice(&(ts as u64).to_be_bytes());
			data[9..25].copy_from_slice(&fp_id);
			data[25..33].copy_from_slice(&ua_hash);

			let mut mac = HmacSha256::new_from_slice(b"test-secret").unwrap();
			mac.update(&data);
			let sig = mac.finalize().into_bytes();

			let mut token = Vec::with_capacity(FP_TOKEN_LEN);
			token.extend_from_slice(&data);
			token.extend_from_slice(&sig);
			URL_SAFE_NO_PAD.encode(token)
		};

		let decoded = URL_SAFE_NO_PAD.decode(token.as_bytes()).unwrap();
		assert_eq!(decoded.len(), FP_TOKEN_LEN);
		assert_eq!(decoded[0], FP_VERSION);
		assert_eq!(&decoded[9..25], &fp_id);
		assert_eq!(&decoded[25..33], &ua_hash);

		let mut mac = HmacSha256::new_from_slice(b"test-secret").unwrap();
		mac.update(&decoded[..(1 + 8 + 16 + 8)]);
		assert!(mac.verify_slice(&decoded[(1 + 8 + 16 + 8)..]).is_ok());

		// Header suspicion helper sanity.
		let mut headers = HeaderMap::new();
		headers.insert("user-agent", HeaderValue::from_static("curl/8.0.0"));
		assert!(is_suspicious_headers(&headers));
	}

	#[test]
	fn ua_parse_chrome_major() {
		assert_eq!(
			parse_chrome_family_major("mozilla/5.0 chrome/131.0.0.0 safari/537.36"),
			Some(131)
		);
		assert_eq!(
			parse_chrome_family_major("mozilla/5.0 edg/132.0.0.0 chrome/132.0.0.0 safari/537.36"),
			Some(132)
		);
		assert_eq!(
			parse_chrome_family_major("mozilla/5.0 (iphone) crios/132.0.0.0 mobile/ safari/604.1"),
			Some(132)
		);
	}

	#[test]
	fn ua_parse_ios_os_major() {
		let ua = "mozilla/5.0 (iphone; cpu iphone os 26_2 like mac os x) applewebkit/605.1.15 (khtml, like gecko) version/26.0 mobile/15e148 safari/604.1";
		assert_eq!(parse_ios_os_major(&ua.to_ascii_lowercase()), Some(26));
	}

	// Note: Chrome-family version gating runs before iOS OS-major gating, so
	// iOS Chrome UAs will be evaluated as Chromium first.
}
