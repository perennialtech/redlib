use arc_swap::ArcSwap;
use bytes::Buf;
use cached::proc_macro::cached;
use futures_lite::future::block_on;
use futures_lite::{future::Boxed, FutureExt};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{header, Method, Request, Response, Uri};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use libflate::gzip;
#[cfg(feature = "tor")]
use hyper_tls::native_tls::TlsConnector;
#[cfg(feature = "tor")]
use log::{error, info, trace, warn};
#[cfg(not(feature = "tor"))]
use log::{error, trace, warn};
use percent_encoding::{percent_encode, CONTROLS};
use serde_json::Value;

#[cfg(feature = "tor")]
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicU16};
use std::sync::{Arc, LazyLock};
#[cfg(feature = "tor")]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io, result::Result};

use crate::body::{empty, full, Body};
#[cfg(any(feature = "tor", test))]
use crate::config::get_setting;
use crate::dbg_msg;
use crate::oauth::{force_refresh_token, token_daemon, Oauth, OauthBackendImpl};
use crate::server::RequestExt;
use crate::utils::{format_url, Post};

#[cfg(not(feature = "tor"))]
use hyper_util::client::legacy::connect::HttpConnector;

#[cfg(feature = "tor")]
use arti_client::config::TorClientConfigBuilder;
#[cfg(feature = "tor")]
use arti_client::TorClient;
#[cfg(feature = "tor")]
use tor_rtcompat::PreferredRuntime;

#[cfg(not(feature = "tor"))]
const REDDIT_URL_BASE: &str = "https://oauth.reddit.com";
#[cfg(not(feature = "tor"))]
const REDDIT_URL_BASE_HOST: &str = "oauth.reddit.com";

#[cfg(feature = "tor")]
const REDDIT_URL_BASE: &str = "https://oauth.reddittorjg6rue252oqsxryoxengawnmo46qy4kyii5wtqnwfj4ooad.onion";
#[cfg(feature = "tor")]
const REDDIT_URL_BASE_HOST: &str = "oauth.reddittorjg6rue252oqsxryoxengawnmo46qy4kyii5wtqnwfj4ooad.onion";

#[cfg(not(feature = "tor"))]
const REDDIT_SHORT_URL_BASE: &str = "https://redd.it";
#[cfg(not(feature = "tor"))]
const REDDIT_SHORT_URL_BASE_HOST: &str = "redd.it";

#[cfg(feature = "tor")]
const REDDIT_SHORT_URL_BASE: &str = "https://redditdotzhmh3mao6r5i2j7speppwqkizwo7vksy3mbz5iz7rlhocyd.onion";
#[cfg(feature = "tor")]
const REDDIT_SHORT_URL_BASE_HOST: &str = "redditdotzhmh3mao6r5i2j7speppwqkizwo7vksy3mbz5iz7rlhocyd.onion";

#[cfg(not(feature = "tor"))]
const ALTERNATIVE_REDDIT_URL_BASE: &str = "https://www.reddit.com";
#[cfg(not(feature = "tor"))]
const ALTERNATIVE_REDDIT_URL_BASE_HOST: &str = "www.reddit.com";

#[cfg(feature = "tor")]
const ALTERNATIVE_REDDIT_URL_BASE: &str = "https://www.reddittorjg6rue252oqsxryoxengawnmo46qy4kyii5wtqnwfj4ooad.onion";
#[cfg(feature = "tor")]
const ALTERNATIVE_REDDIT_URL_BASE_HOST: &str = "www.reddittorjg6rue252oqsxryoxengawnmo46qy4kyii5wtqnwfj4ooad.onion";

#[cfg(feature = "tor")]
const DEFAULT_ARTI_PATH: &str = "/tmp/arti";
#[cfg(feature = "tor")]
const DEFAULT_TOR_HARD_RESET_FAILURE_STREAK: u16 = 3;
#[cfg(feature = "tor")]
const ARTI_ROTATED_STATE_BACKUP_LIMIT: usize = 2;

fn format_client_connect_error(err: &hyper_util::client::legacy::Error) -> String {
	let mut msg = err.to_string();
	let mut source = std::error::Error::source(err);
	while let Some(next) = source {
		msg.push_str(": ");
		msg.push_str(&next.to_string());
		source = next.source();
	}
	msg
}

// --- Non-Tor client ---

#[cfg(not(feature = "tor"))]
pub static HTTPS_CONNECTOR: LazyLock<HttpsConnector<HttpConnector>> = LazyLock::new(HttpsConnector::new);

#[cfg(not(feature = "tor"))]
pub static CLIENT: LazyLock<ArcSwap<Client<HttpsConnector<HttpConnector>, Body>>> =
	LazyLock::new(|| ArcSwap::new(Arc::new(Client::builder(TokioExecutor::new()).build::<_, Body>(HTTPS_CONNECTOR.clone()))));

// --- Tor client ---

#[cfg(feature = "tor")]
#[derive(Clone, Debug)]
struct ArtiPaths {
	root: PathBuf,
	state: PathBuf,
	cache: PathBuf,
}

#[cfg(feature = "tor")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum TorRebuildMode {
	Soft,
	HardReset,
}

#[cfg(feature = "tor")]
fn arti_paths() -> ArtiPaths {
	let root = PathBuf::from(get_setting("REDLIB_ARTI_PATH").unwrap_or_else(|| DEFAULT_ARTI_PATH.to_string()));
	ArtiPaths {
		state: root.join("state"),
		cache: root.join("cache"),
		root,
	}
}

#[cfg(feature = "tor")]
fn prepare_arti_directories(paths: &ArtiPaths) {
	std::fs::create_dir_all(&paths.root).ok();
	std::fs::create_dir_all(&paths.state).ok();
	std::fs::create_dir_all(&paths.cache).ok();

	use std::os::unix::fs::PermissionsExt;
	for path in [&paths.root, &paths.state, &paths.cache] {
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).ok();
	}
}

#[cfg(feature = "tor")]
fn rotate_arti_subdir(dir: &Path) -> Result<Option<PathBuf>, io::Error> {
	if !dir.exists() {
		return Ok(None);
	}

	let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
	let name = dir.file_name().and_then(|name| name.to_str()).unwrap_or("arti");
	let rotated = dir.with_file_name(format!("{name}.recovered-{timestamp}"));
	std::fs::rename(dir, &rotated)?;
	Ok(Some(rotated))
}

#[cfg(feature = "tor")]
fn cleanup_rotated_arti_state(paths: &ArtiPaths) {
	let Ok(entries) = std::fs::read_dir(&paths.root) else {
		return;
	};

	let mut rotated = entries
		.filter_map(Result::ok)
		.map(|entry| entry.path())
		.filter(|path| {
			path.file_name()
				.and_then(|name| name.to_str())
				.map(|name| name.starts_with("state.recovered-") || name.starts_with("cache.recovered-"))
				.unwrap_or(false)
		})
		.collect::<Vec<_>>();

	rotated.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

	for stale in rotated.into_iter().skip(ARTI_ROTATED_STATE_BACKUP_LIMIT) {
		let result = if stale.is_dir() {
			std::fs::remove_dir_all(&stale)
		} else {
			std::fs::remove_file(&stale)
		};

		if let Err(err) = result {
			warn!("Failed to clean up rotated Arti path {}: {}", stale.display(), err);
		}
	}
}

#[cfg(feature = "tor")]
fn hard_reset_arti_runtime() -> Result<(), String> {
	let paths = arti_paths();
	std::fs::create_dir_all(&paths.root).map_err(|err| format!("Failed to prepare Arti root {}: {err}", paths.root.display()))?;

	if let Some(rotated) = rotate_arti_subdir(&paths.state).map_err(|err| format!("Failed to rotate Arti state {}: {err}", paths.state.display()))? {
		warn!("Rotated Arti state directory to {}", rotated.display());
	}
	if let Some(rotated) = rotate_arti_subdir(&paths.cache).map_err(|err| format!("Failed to rotate Arti cache {}: {err}", paths.cache.display()))? {
		warn!("Rotated Arti cache directory to {}", rotated.display());
	}

	prepare_arti_directories(&paths);
	cleanup_rotated_arti_state(&paths);
	Ok(())
}

#[cfg(feature = "tor")]
fn build_tor_config() -> arti_client::TorClientConfig {
	let paths = arti_paths();
	prepare_arti_directories(&paths);

	info!(
		"Using Arti directories - State: {}, Cache: {}",
		paths.state.display(),
		paths.cache.display()
	);

	let mut config_builder = TorClientConfigBuilder::from_directories(paths.state.clone(), paths.cache.clone());

	let tor_connect_timeout_secs = get_setting("REDLIB_TOR_CONNECT_TIMEOUT_SECS")
		.and_then(|v| v.parse::<u64>().ok())
		.unwrap_or(180);
	let tor_circuit_request_timeout_secs = get_setting("REDLIB_TOR_CIRCUIT_REQUEST_TIMEOUT_SECS")
		.and_then(|v| v.parse::<u64>().ok())
		.unwrap_or(180);
	let tor_circuit_request_max_retries = get_setting("REDLIB_TOR_CIRCUIT_REQUEST_MAX_RETRIES")
		.and_then(|v| v.parse::<u32>().ok())
		.unwrap_or(32);

	config_builder.address_filter().allow_onion_addrs(true);
	config_builder
		.stream_timeouts()
		.connect_timeout(std::time::Duration::from_secs(tor_connect_timeout_secs));
	config_builder
		.circuit_timing()
		.request_timeout(std::time::Duration::from_secs(tor_circuit_request_timeout_secs))
		.request_max_retries(tor_circuit_request_max_retries);

	info!(
		"Using Tor timeouts: connect={}s, circuit_request={}s, circuit_retries={}",
		tor_connect_timeout_secs, tor_circuit_request_timeout_secs, tor_circuit_request_max_retries
	);

	config_builder.build().expect("Failed to build Tor client config")
}

#[cfg(feature = "tor")]
fn tor_hard_reset_failure_streak() -> u16 {
	std::env::var("REDLIB_TOR_HARD_RESET_FAILURE_STREAK")
		.ok()
		.and_then(|value| value.parse::<u16>().ok())
		.filter(|value| *value > 0)
		.unwrap_or(DEFAULT_TOR_HARD_RESET_FAILURE_STREAK)
}

#[cfg(feature = "tor")]
fn is_tor_connectivity_error(err: &str) -> bool {
	let err = err.to_ascii_lowercase();
	[
		"tor:",
		"hidden service",
		"rendezvous",
		"introduction point",
		"failed to obtain circuit",
		"circuit took too long",
		"operation timed out",
		"connection closed before message completed",
		"unable to connect to hidden service",
		"client error (connect)",
	]
	.into_iter()
	.any(|pattern| err.contains(pattern))
}

#[cfg(feature = "tor")]
fn register_tor_failure(failure: Option<&str>) -> (u16, TorRebuildMode) {
	let streak = if failure.is_none() || failure.is_some_and(is_tor_connectivity_error) {
		TOR_FAILURE_STREAK.fetch_add(1, Ordering::SeqCst).saturating_add(1)
	} else {
		TOR_FAILURE_STREAK.store(0, Ordering::SeqCst);
		0
	};

	let mode = if streak >= tor_hard_reset_failure_streak() {
		TorRebuildMode::HardReset
	} else {
		TorRebuildMode::Soft
	};

	(streak, mode)
}

#[cfg(feature = "tor")]
pub(crate) fn mark_tor_connection_healthy() {
	TOR_FAILURE_STREAK.store(0, Ordering::SeqCst);
}

#[cfg(feature = "tor")]
async fn create_bootstrapped_tor_client(mode: TorRebuildMode) -> Result<TorClient<PreferredRuntime>, String> {
	if matches!(mode, TorRebuildMode::HardReset) {
		hard_reset_arti_runtime()?;
	}

	TorClient::with_runtime(PreferredRuntime::current().expect("Could not get runtime"))
		.config(build_tor_config())
		.create_bootstrapped()
		.await
		.map_err(|err| err.to_string())
}

// Custom Tor transport connector implementing tower::Service<Uri>.
// TLS is layered by hyper-tls so this connector only dials DataStream.
#[cfg(feature = "tor")]
mod tor_connector {
	use super::*;
	use arti_client::DataStream;
	use hyper_util::client::legacy::connect::{Connected, Connection};
	use hyper_util::rt::TokioIo;
	use pin_project_lite::pin_project;
	use std::fmt;
	use std::future::Future;
	use std::pin::Pin;
	use std::task::{Context, Poll};
	use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

	pin_project! {
		pub struct ArtiStream {
			#[pin]
			inner: DataStream,
		}
	}

	impl ArtiStream {
		pub fn new(inner: DataStream) -> Self {
			Self { inner }
		}
	}

	impl fmt::Debug for ArtiStream {
		fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
			f.write_str("ArtiStream(..)")
		}
	}

	impl AsyncRead for ArtiStream {
		fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
			self.project().inner.poll_read(cx, buf)
		}
	}

	impl AsyncWrite for ArtiStream {
		fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
			self.project().inner.poll_write(cx, buf)
		}

		fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			self.project().inner.poll_flush(cx)
		}

		fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			self.project().inner.poll_shutdown(cx)
		}
	}

	impl Connection for ArtiStream {
		fn connected(&self) -> Connected {
			Connected::new()
		}
	}

	#[derive(Clone)]
	pub struct ArtiConnector {
		tor_client: TorClient<PreferredRuntime>,
	}

	impl ArtiConnector {
		pub fn new(tor_client: TorClient<PreferredRuntime>) -> Self {
			Self { tor_client }
		}
	}

	impl tower::Service<Uri> for ArtiConnector {
		type Response = TokioIo<ArtiStream>;
		type Error = Box<dyn std::error::Error + Send + Sync>;
		type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

		fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
			Poll::Ready(Ok(()))
		}

		fn call(&mut self, uri: Uri) -> Self::Future {
			let tor_client = self.tor_client.clone();

			Box::pin(async move {
				let host = uri.host().ok_or("URI has no host")?;
				let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
					Some("https") => 443,
					_ => 80,
				});

				let data_stream = tor_client
					.connect((host, port))
					.await
					.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

				Ok(TokioIo::new(ArtiStream::new(data_stream)))
			})
		}
	}
}

#[cfg(feature = "tor")]
use tor_connector::ArtiConnector;

#[cfg(feature = "tor")]
fn build_http_client(tor_client: TorClient<PreferredRuntime>) -> Client<HttpsConnector<ArtiConnector>, Body> {
	let connector = ArtiConnector::new(tor_client);
	let mut tls = TlsConnector::builder();
	tls.danger_accept_invalid_certs(true);
	tls.danger_accept_invalid_hostnames(true);
	let https = HttpsConnector::from((connector, tls.build().expect("Failed to create Tor TLS connector").into()));
	Client::builder(TokioExecutor::new()).build::<_, Body>(https)
}

#[cfg(feature = "tor")]
pub static TOR_CLIENT: LazyLock<ArcSwap<TorClient<PreferredRuntime>>> = LazyLock::new(|| {
	let client = block_on(async {
		info!("Creating and bootstrapping Tor client...");
		match create_bootstrapped_tor_client(TorRebuildMode::Soft).await {
			Ok(client) => {
				mark_tor_connection_healthy();
				info!("Tor client created and bootstrapped successfully!");
				client
			}
			Err(first_err) => {
				error!("Failed to create and bootstrap Tor client with existing state: {}", first_err);
				warn!("Attempting a hard reset of Arti state/cache before retrying bootstrap...");
				match create_bootstrapped_tor_client(TorRebuildMode::HardReset).await {
					Ok(client) => {
						mark_tor_connection_healthy();
						info!("Tor client bootstrapped successfully after hard reset");
						client
					}
					Err(recovery_err) => {
						error!("Failed to create and bootstrap Tor client after hard reset: {}", recovery_err);
						panic!("Cannot start without Tor connection: {}", recovery_err);
					}
				}
			}
		}
	});

	ArcSwap::new(Arc::new(client))
});

#[cfg(feature = "tor")]
pub static CLIENT: LazyLock<ArcSwap<Client<HttpsConnector<ArtiConnector>, Body>>> = LazyLock::new(|| {
	let tor_client = (**TOR_CLIENT.load()).clone();
	ArcSwap::new(Arc::new(build_http_client(tor_client)))
});

#[cfg(feature = "tor")]
static TOR_IS_REBUILDING: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "tor")]
static TOR_FAILURE_STREAK: AtomicU16 = AtomicU16::new(0);

#[cfg(feature = "tor")]
async fn wait_for_tor_rebuild_to_finish() {
	while TOR_IS_REBUILDING.load(Ordering::SeqCst) {
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	}
}

/// Rebuild the Tor client and HTTP client when circuits are broken.
/// Uses an atomic flag to prevent concurrent rebuilds.
#[cfg(feature = "tor")]
async fn rebuild_tor_connection_with_mode(mode: TorRebuildMode) {
	// If already rebuilding, don't start another one
	if TOR_IS_REBUILDING.swap(true, Ordering::SeqCst) {
		info!("Tor circuit rebuild already in progress, waiting for completion");
		wait_for_tor_rebuild_to_finish().await;
		return;
	}

	match mode {
		TorRebuildMode::Soft => warn!("Rebuilding Tor client due to connection failure..."),
		TorRebuildMode::HardReset => warn!("Hard-resetting Arti state/cache before rebuilding Tor client..."),
	}

	match create_bootstrapped_tor_client(mode).await {
		Ok(new_tor) => {
			let new_http = build_http_client(new_tor.clone());
			TOR_CLIENT.store(Arc::new(new_tor));
			CLIENT.store(Arc::new(new_http));
			if matches!(mode, TorRebuildMode::HardReset) {
				mark_tor_connection_healthy();
				info!("Tor client rebuilt successfully after hard reset");
			} else {
				info!("Tor client rebuilt successfully");
			}
		}
		Err(e) => {
			error!("Failed to rebuild Tor client: {}", e);
		}
	}

	TOR_IS_REBUILDING.store(false, Ordering::SeqCst);
}

#[cfg(feature = "tor")]
pub(crate) async fn recover_tor_connection(context: &str, failure: Option<&str>) {
	let (streak, mode) = register_tor_failure(failure);
	let action = if matches!(mode, TorRebuildMode::HardReset) {
		"hard-resetting Arti state/cache and rebuilding Tor client"
	} else {
		"rebuilding Tor client"
	};

	match failure {
		Some(err) if streak > 0 => warn!("{context} failed over Tor (failure streak {streak}, {action}): {err}"),
		Some(err) => warn!("{context} failed over Tor ({action}): {err}"),
		None if streak > 0 => warn!("{context} timed out over Tor (failure streak {streak}, {action})"),
		None => warn!("{context} timed out over Tor ({action})"),
	}

	rebuild_tor_connection_with_mode(mode).await;
}

pub static OAUTH_CLIENT: LazyLock<ArcSwap<Oauth>> = LazyLock::new(|| {
	let client = block_on(Oauth::new());
	tokio::spawn(token_daemon());
	ArcSwap::new(client.into())
});

pub static OAUTH_RATELIMIT_REMAINING: AtomicU16 = AtomicU16::new(99);

pub static OAUTH_IS_ROLLING_OVER: AtomicBool = AtomicBool::new(false);

const URL_PAIRS: [(&str, &str); 2] = [
	(ALTERNATIVE_REDDIT_URL_BASE, ALTERNATIVE_REDDIT_URL_BASE_HOST),
	(REDDIT_SHORT_URL_BASE, REDDIT_SHORT_URL_BASE_HOST),
];

/// Gets the canonical path for a resource on Reddit. This is accomplished by
/// making a `HEAD` request to Reddit at the path given in `path`.
///
/// This function returns `Ok(Some(path))`, where `path`'s value is identical
/// to that of the value of the argument `path`, if Reddit responds to our
/// `HEAD` request with a 2xx-family HTTP code. It will also return an
/// `Ok(Some(String))` if Reddit responds to our `HEAD` request with a
/// `Location` header in the response, and the HTTP code is in the 3xx-family;
/// the `String` will contain the path as reported in `Location`. The return
/// value is `Ok(None)` if Reddit responded with a 3xx, but did not provide a
/// `Location` header. An `Err(String)` is returned if Reddit responds with a
/// 429, or if we were unable to decode the value in the `Location` header.
#[cached(size = 1024, time = 600, result = true)]
#[async_recursion::async_recursion]
pub async fn canonical_path(path: String, tries: i8) -> Result<Option<String>, String> {
	if tries == 0 {
		return Ok(None);
	}

	// for each URL pair, try the HEAD request
	let res = {
		let mut res = None;
		for (url_base, url_base_host) in URL_PAIRS {
			res = reddit_short_head(path.clone(), true, url_base, url_base_host).await.ok();
			if let Some(res) = &res {
				if !res.status().is_client_error() {
					break;
				}
			}
		}
		res
	};

	let res = res.ok_or_else(|| "Unable to make HEAD request to Reddit.".to_string())?;
	let status = res.status().as_u16();
	let policy_error = res.headers().get(header::RETRY_AFTER).is_some();

	match status {
		// If Reddit responds with a 2xx, then the path is already canonical.
		200..=299 => Ok(Some(path)),

		// If Reddit responds with a 301, then the path is redirected.
		301 => match res.headers().get(header::LOCATION) {
			Some(val) => {
				let Ok(original) = val.to_str() else {
					return Err("Unable to decode Location header.".to_string());
				};

				let stripped_uri = original.strip_suffix(".json").unwrap_or(original).split('?').next().unwrap_or_default();
				let uri = format_url(stripped_uri);

				// Decrement tries and try again
				canonical_path(uri, tries - 1).await
			}
			None => Ok(None),
		},

		300..=399 => Ok(None),

		// Rate limiting
		429 => Err("Too many requests.".to_string()),

		// Special condition rate limiting
		403 if policy_error => Err("Too many requests.".to_string()),

		_ => Ok(
			res
				.headers()
				.get(header::LOCATION)
				.map(|val| percent_encode(val.as_bytes(), CONTROLS).to_string().trim_start_matches(REDDIT_URL_BASE).to_string()),
		),
	}
}

pub async fn proxy(req: Request<Body>, format: &str) -> Result<Response<Body>, String> {
	let mut url = format!("{format}?{}", req.uri().query().unwrap_or_default());

	// For each parameter in request
	for (name, value) in &req.params() {
		// Fill the parameter value in the url
		url = url.replace(&format!("{{{name}}}"), value);
	}

	stream(&url, &req).await
}

fn sanitize_stream_response(res: Response<Incoming>) -> Response<Body> {
	// Map the response body from Incoming to our Body type
	let (parts, incoming) = res.into_parts();
	let body: Body = incoming.map_err(|e| e.to_string()).boxed();
	let mut res = Response::from_parts(parts, body);

	let mut rm = |key: &str| res.headers_mut().remove(key);

	rm("access-control-expose-headers");
	rm("server");
	rm("vary");
	rm("etag");
	rm("x-cdn");
	rm("x-cdn-client-region");
	rm("x-cdn-name");
	rm("x-cdn-server-region");
	rm("x-reddit-cdn");
	rm("x-reddit-video-features");
	rm("Nel");
	rm("Report-To");

	res
}

async fn stream(url: &str, req: &Request<Body>) -> Result<Response<Body>, String> {
	// First parameter is target URL (mandatory).
	let parsed_uri = url.parse::<Uri>().map_err(|_| "Couldn't parse URL".to_string())?;

	let make_stream_request = || -> Result<Request<Body>, String> {
		let mut builder = Request::get(parsed_uri.clone());

		// Copy useful headers from original request
		for &key in &["Range", "If-Modified-Since", "Cache-Control"] {
			if let Some(value) = req.headers().get(key) {
				builder = builder.header(key, value);
			}
		}

		// Add User-Agent header of the currently spoofed device
		{
			let client = OAUTH_CLIENT.load_full();
			builder = builder.header("User-Agent", client.user_agent());
		}

		builder.body(empty()).map_err(|_| "Couldn't build empty body in stream".to_string())
	};

	#[cfg(feature = "tor")]
	{
		let mut last_err = String::new();
		let context = format!("Stream request to {url}");
		for attempt in 1..=3 {
			let stream_request = make_stream_request()?;
			let client = CLIENT.load_full();
			match client.request(stream_request).await {
				Ok(res) => {
					mark_tor_connection_healthy();
					return Ok(sanitize_stream_response(res));
				}
				Err(e) => {
					last_err = format_client_connect_error(&e);
					if attempt == 3 {
						return Err(last_err);
					}
					recover_tor_connection(&format!("{context} (retry {attempt}/2)"), Some(last_err.as_str())).await;
				}
			}
		}
		return Err(last_err);
	}

	#[cfg(not(feature = "tor"))]
	{
		let stream_request = make_stream_request()?;
		let client = CLIENT.load_full();
		client
			.request(stream_request)
			.await
			.map(sanitize_stream_response)
			.map_err(|e| format_client_connect_error(&e))
	}
}

/// Makes a GET request to Reddit at `path`. By default, this will honor HTTP
/// 3xx codes Reddit returns and will automatically redirect.
fn reddit_get(path: String, quarantine: bool) -> Boxed<Result<Response<Body>, String>> {
	request(&Method::GET, path, true, quarantine, REDDIT_URL_BASE, REDDIT_URL_BASE_HOST)
}

/// Makes a HEAD request to Reddit at `path, using the short URL base. This will not follow redirects.
fn reddit_short_head(path: String, quarantine: bool, base_path: &'static str, host: &'static str) -> Boxed<Result<Response<Body>, String>> {
	request(&Method::HEAD, path, false, quarantine, base_path, host)
}

/// Build a Reddit API request with shuffled headers.
fn build_reddit_request(method: &Method, url: &str, quarantine: bool, host: &str) -> Result<Request<Body>, String> {
	let mut headers: Vec<(String, String)> = vec![
		("Host".into(), host.into()),
		("Accept-Encoding".into(), if *method == Method::GET { "gzip".into() } else { "identity".into() }),
		(
			"Cookie".into(),
			if quarantine {
				"_options=%7B%22pref_quarantine_optin%22%3A%20true%2C%20%22pref_gated_sr_optin%22%3A%20true%7D".into()
			} else {
				"".into()
			},
		),
	];

	{
		let client = OAUTH_CLIENT.load_full();
		for (key, value) in client.headers_map.clone() {
			headers.push((key, value));
		}
	}

	// shuffle headers
	fastrand::shuffle(&mut headers);

	let mut builder = Request::builder().method(method).uri(url);

	for (key, value) in headers {
		builder = builder.header(key, value);
	}

	builder.body(empty()).map_err(|_| "Post url contains non-ASCII characters".to_string())
}

/// Execute a single request attempt against Reddit, handling redirects and decompression.
async fn execute_request(method: &'static Method, path: &str, redirect: bool, quarantine: bool, base_path: &'static str, host: &'static str) -> Result<Response<Body>, String> {
	let url = format!("{base_path}{path}");
	let client = CLIENT.load_full();

	let req = build_reddit_request(method, &url, quarantine, host)?;

	match client.request(req).await {
		Ok(response) => {
			// Map the response body from Incoming to our Body type
			let (parts, incoming) = response.into_parts();
			let body: Body = incoming.map_err(|e| e.to_string()).boxed();
			let mut response = Response::from_parts(parts, body);

			// Reddit may respond with a 3xx. Decide whether or not to
			// redirect based on caller params.
			if response.status().is_redirection() {
				if !redirect {
					return Ok(response);
				};
				let location_header = response.headers().get(header::LOCATION);
				if location_header == Some(&HeaderValue::from_static(ALTERNATIVE_REDDIT_URL_BASE)) {
					return Err("Reddit response was invalid".to_string());
				}
				return request(
					method,
					location_header
						.map(|val| {
							let new_path = percent_encode(val.as_bytes(), CONTROLS)
								.to_string()
								.trim_start_matches(REDDIT_URL_BASE)
								.trim_start_matches(ALTERNATIVE_REDDIT_URL_BASE)
								.to_string();
							format!("{new_path}{}raw_json=1", if new_path.contains('?') { "&" } else { "?" })
						})
						.unwrap_or_default()
						.to_string(),
					true,
					quarantine,
					base_path,
					host,
				)
				.await;
			};

			match response.headers().get(header::CONTENT_ENCODING) {
				// Content not compressed.
				None => Ok(response),

				// Content encoded (hopefully with gzip).
				Some(hdr) => {
					match hdr.to_str() {
						Ok(val) => match val {
							"gzip" => {}
							"identity" => return Ok(response),
							_ => return Err("Reddit response was encoded with an unsupported compressor".to_string()),
						},
						Err(_) => return Err("Reddit response was invalid".to_string()),
					}

					// Decompress gzip body
					let mut decompressed: Vec<u8>;
					{
						let aggregated_body = std::mem::replace(response.body_mut(), empty())
							.collect()
							.await
							.map_err(|e| e.to_string())?;
						let mut reader = aggregated_body.aggregate().reader();

						let mut decoder = match gzip::Decoder::new(&mut reader) {
							Ok(decoder) => decoder,
							Err(e) => return Err(e.to_string()),
						};

						decompressed = Vec::<u8>::new();
						if let Err(e) = io::copy(&mut decoder, &mut decompressed) {
							return Err(e.to_string());
						};
					}

					response.headers_mut().remove(header::CONTENT_ENCODING);
					response.headers_mut().insert(header::CONTENT_LENGTH, decompressed.len().into());
					*(response.body_mut()) = full(decompressed);

					Ok(response)
				}
			}
		}
		Err(e) => {
			dbg_msg!("{method} {REDDIT_URL_BASE}{path}: {}", e);
			Err(format_client_connect_error(&e))
		}
	}
}

/// Makes a request to Reddit. If `redirect` is `true`, `request_with_redirect`
/// will recurse on the URL that Reddit provides in the Location HTTP header
/// in its response. On Tor, connection failures trigger circuit rebuilds and
/// bounded retries.
fn request(method: &'static Method, path: String, redirect: bool, quarantine: bool, base_path: &'static str, host: &'static str) -> Boxed<Result<Response<Body>, String>> {
	async move {
		#[cfg(feature = "tor")]
		{
			let mut result = execute_request(method, &path, redirect, quarantine, base_path, host).await;
			for attempt in 1..=2 {
				if result.is_ok() {
					mark_tor_connection_healthy();
					return result;
				}

				if let Err(e) = result.as_ref() {
					recover_tor_connection(&format!("Request to {path} (retry {attempt}/2)"), Some(e.as_str())).await;
				} else {
					recover_tor_connection(&format!("Request to {path} (retry {attempt}/2)"), None).await;
				}
				result = execute_request(method, &path, redirect, quarantine, base_path, host).await;
			}
			if result.is_ok() {
				mark_tor_connection_healthy();
			}
			return result;
		}

		#[cfg(not(feature = "tor"))]
		{
			execute_request(method, &path, redirect, quarantine, base_path, host).await
		}
	}
	.boxed()
}

/// Make a request to a Reddit API and parse the JSON response
#[cached(size = 100, time = 30, result = true)]
pub async fn json(path: String, quarantine: bool) -> Result<Value, String> {
	// Closure to quickly build errors
	let err = |msg: &str, e: String, path: String| -> Result<Value, String> {
		Err(format!("{msg}: {e} | {path}"))
	};

	// First, handle rolling over the OAUTH_CLIENT if need be.
	let current_rate_limit = OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst);
	let is_rolling_over = OAUTH_IS_ROLLING_OVER.load(Ordering::SeqCst);
	if current_rate_limit < 10 && !is_rolling_over {
		warn!("Rate limit {current_rate_limit} is low. Spawning force_refresh_token()");
		tokio::spawn(force_refresh_token());
	}
	OAUTH_RATELIMIT_REMAINING.fetch_sub(1, Ordering::SeqCst);

	// Fetch the url...
	match reddit_get(path.clone(), quarantine).await {
		Ok(response) => {
			let status = response.status();

			let reset: Option<String> = if let (Some(remaining), Some(reset), Some(used)) = (
				response.headers().get("x-ratelimit-remaining").and_then(|val| val.to_str().ok().map(|s| s.to_string())),
				response.headers().get("x-ratelimit-reset").and_then(|val| val.to_str().ok().map(|s| s.to_string())),
				response.headers().get("x-ratelimit-used").and_then(|val| val.to_str().ok().map(|s| s.to_string())),
			) {
				trace!(
					"Ratelimit remaining: Header says {remaining}, we have {current_rate_limit}. Resets in {reset}. Rollover: {}. Ratelimit used: {used}",
					if is_rolling_over { "yes" } else { "no" },
				);

				if let Ok(val) = remaining.parse::<f32>() {
					OAUTH_RATELIMIT_REMAINING.store(val.round() as u16, Ordering::SeqCst);
				}

				Some(reset)
			} else {
				None
			};

			// asynchronously aggregate the chunks of the body
			match response.into_body().collect().await {
				Ok(collected) => {
					let body = collected.aggregate();
					let has_remaining = body.has_remaining();

					if !has_remaining {
						// Rate limited, so spawn a force_refresh_token()
						tokio::spawn(force_refresh_token());
						return match reset {
							Some(val) => Err(format!(
								"Reddit rate limit exceeded. Try refreshing in a few seconds.\
								 Rate limit will reset in: {val}"
							)),
							None => Err("Reddit rate limit exceeded".to_string()),
						};
					}

					// Parse the response from Reddit as JSON
					match serde_json::from_reader(body.reader()) {
						Ok(value) => {
							let json: Value = value;

							// If user is suspended
							if let Some(data) = json.get("data") {
								if let Some(is_suspended) = data.get("is_suspended").and_then(Value::as_bool) {
									if is_suspended {
										return Err("suspended".into());
									}
								}
							}

							// If Reddit returned an error
							if json["error"].is_i64() {
								// OAuth token has expired; http status 401
								if json["message"] == "Unauthorized" {
									error!("Forcing a token refresh");
									let () = force_refresh_token().await;
									return Err("OAuth token has expired. Please refresh the page!".to_string());
								}

								// Handle quarantined
								if json["reason"] == "quarantined" {
									return Err("quarantined".into());
								}
								// Handle gated
								if json["reason"] == "gated" {
									return Err("gated".into());
								}
								// Handle private subs
								if json["reason"] == "private" {
									return Err("private".into());
								}
								// Handle banned subs
								if json["reason"] == "banned" {
									return Err("banned".into());
								}

								Err(format!("Reddit error {} \"{}\": {} | {path}", json["error"], json["reason"], json["message"]))
							} else {
								Ok(json)
							}
						}
						Err(e) => {
							error!("Got an invalid response from reddit {e}. Status code: {status}");
							if status.is_server_error() {
								Err("Reddit is having issues, check if there's an outage".to_string())
							} else {
								err("Failed to parse page JSON data", e.to_string(), path)
							}
						}
					}
				}
				Err(e) => err("Failed receiving body from Reddit", e.to_string(), path),
			}
		}
		Err(e) => err("Couldn't send request to Reddit", e, path),
	}
}

async fn self_check(sub: &str) -> Result<(), String> {
	let query = format!("/r/{sub}/hot.json?&raw_json=1");

	match Post::fetch(&query, true).await {
		Ok(_) => Ok(()),
		Err(e) => Err(e),
	}
}

pub async fn rate_limit_check() -> Result<(), String> {
	// First, test the Oauth client
	if matches!(OAUTH_CLIENT.load().backend, OauthBackendImpl::GenericWeb(_)) {
		warn!("[⚠️] Cannot perform rate limit check, running as GenericWeb. Skipping check.");
		return Ok(());
	}

	self_check("reddit").await?;
	if OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst) != 99 {
		return Err(format!("Rate limit check 1 failed: expected 99, got {}", OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst)));
	}
	force_refresh_token().await;
	self_check("rust").await?;
	if OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst) != 99 {
		return Err(format!("Rate limit check 2 failed: expected 99, got {}", OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst)));
	}

	Ok(())
}

#[cfg(test)]
use sealed_test::prelude::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_rate_limit_check() {
	rate_limit_check().await.unwrap();
}

#[test]
#[sealed_test(env = [("REDLIB_DEFAULT_SUBSCRIPTIONS", "rust")])]
fn test_default_subscriptions() {
	tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
		let subscriptions = get_setting("REDLIB_DEFAULT_SUBSCRIPTIONS");
		assert!(subscriptions.is_some());

		// check rate limit
		rate_limit_check().await.unwrap();
	});
}

#[cfg(test)]
const POPULAR_URL: &str = "/r/popular/hot.json?&raw_json=1&geo_filter=GLOBAL";

#[tokio::test(flavor = "multi_thread")]
async fn test_localization_popular() {
	let val = json(POPULAR_URL.to_string(), false).await.unwrap();
	assert_eq!("GLOBAL", val["data"]["geo_filter"].as_str().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_obfuscated_share_link() {
	let share_link = "/r/rust/s/kPgq8WNHRK".into();
	// Correct link without share parameters
	let canonical_link = "/r/rust/comments/18t5968/why_use_tuple_struct_over_standard_struct/kfbqlbc/".into();
	assert_eq!(canonical_path(share_link, 3).await, Ok(Some(canonical_link)));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_private_sub() {
	let link = json("/r/suicide/about.json?raw_json=1".into(), true).await;
	assert!(link.is_err());
	assert_eq!(link, Err("private".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_banned_sub() {
	let link = json("/r/aaa/about.json?raw_json=1".into(), true).await;
	assert!(link.is_err());
	assert_eq!(link, Err("banned".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gated_sub() {
	// quarantine to false to specifically catch when we _don't_ catch it
	let link = json("/r/drugs/about.json?raw_json=1".into(), false).await;
	assert!(link.is_err());
	assert_eq!(link, Err("gated".into()));
}
