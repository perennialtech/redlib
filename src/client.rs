use arc_swap::ArcSwap;
use bytes::Buf;
use cached::proc_macro::cached;
use futures_lite::future::block_on;
use futures_lite::{future::Boxed, FutureExt};
use hyper::header::HeaderValue;
use hyper::{header, Method, Request, Response, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use http_body_util::BodyExt;
use libflate::gzip;
#[cfg(not(feature = "tor"))]
use log::{error, trace, warn};
#[cfg(feature = "tor")]
use log::{error, info, trace, warn};
use percent_encoding::{percent_encode, CONTROLS};
use serde_json::Value;

use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicU16};
use std::sync::{Arc, LazyLock};
use std::{io, result::Result};

use openssl::ssl::{SslConnector, SslMethod};

use crate::body::{Body, full, empty};
use crate::dbg_msg;
#[cfg(any(feature = "tor", test))]
use crate::config::get_setting;
use crate::oauth::{force_refresh_token, token_daemon, Oauth, OauthBackendImpl};
use crate::server::RequestExt;
use crate::utils::{format_url, Post};

#[cfg(not(feature = "tor"))]
use hyper_util::client::legacy::connect::HttpConnector;
#[cfg(not(feature = "tor"))]
use hyper_openssl::client::legacy::HttpsConnector;

#[cfg(feature = "tor")]
use arti_client::TorClient;
#[cfg(feature = "tor")]
use arti_client::config::TorClientConfigBuilder;
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

// --- Android-like TLS cipher suite configuration ---

fn android_ssl_connector() -> openssl::ssl::SslConnectorBuilder {
	let mut builder = SslConnector::builder(SslMethod::tls_client())
		.expect("Failed to create SslConnectorBuilder");

	// TLS 1.3 ciphers (Android default order)
	builder
		.set_ciphersuites("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
		.expect("Failed to set TLS 1.3 ciphersuites");

	// TLS 1.2 ciphers (Android default order, includes CBC/RSA ciphers)
	builder
		.set_cipher_list(
			"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
			 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
			 ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
			 ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:\
			 AES128-GCM-SHA256:AES256-GCM-SHA384:\
			 AES128-SHA:AES256-SHA",
		)
		.expect("Failed to set TLS 1.2 cipher list");

	builder
}

// --- Non-Tor client ---

#[cfg(not(feature = "tor"))]
pub static HTTPS_CONNECTOR: LazyLock<HttpsConnector<HttpConnector>> =
	LazyLock::new(|| {
		HttpsConnector::with_connector(
			HttpConnector::new(),
			android_ssl_connector(),
		).expect("Failed to create HTTPS connector")
	});

#[cfg(not(feature = "tor"))]
pub static CLIENT: LazyLock<ArcSwap<Client<HttpsConnector<HttpConnector>, Body>>> = LazyLock::new(|| {
	ArcSwap::new(Arc::new(
		Client::builder(TokioExecutor::new()).build::<_, Body>(HTTPS_CONNECTOR.clone()),
	))
});

// --- Tor client ---

#[cfg(feature = "tor")]
fn build_tor_config() -> arti_client::TorClientConfig {
	let arti_path = get_setting("REDLIB_ARTI_PATH").unwrap_or_else(|| "/tmp/arti".to_string());

	let state_dir = format!("{}/state", arti_path);
	let cache_dir = format!("{}/cache", arti_path);
	std::fs::create_dir_all(&state_dir).ok();
	std::fs::create_dir_all(&cache_dir).ok();

	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&arti_path, std::fs::Permissions::from_mode(0o700)).ok();

	info!("Using Arti directories - State: {}, Cache: {}", state_dir, cache_dir);

	let mut config_builder = TorClientConfigBuilder::from_directories(
		std::path::PathBuf::from(state_dir),
		std::path::PathBuf::from(cache_dir)
	);

	config_builder.address_filter().allow_onion_addrs(true);
	config_builder.stream_timeouts().connect_timeout(std::time::Duration::from_secs(60));

	config_builder.build().expect("Failed to build Tor client config")
}

// Custom Tor connector implementing tower::Service<Uri>
#[cfg(feature = "tor")]
mod tor_connector {
	use super::*;
	use arti_client::DataStream;
	use hyper::rt::{Read, Write, ReadBufCursor};
	use hyper_util::client::legacy::connect::Connection;
	use hyper_util::rt::TokioIo;
	use pin_project_lite::pin_project;
	use std::future::Future;
	use std::pin::Pin;
	use std::task::{Context, Poll};

	pin_project! {
		/// A stream that is either a raw Tor DataStream or a TLS-wrapped one.
		/// Inner types are wrapped in TokioIo to bridge tokio AsyncRead/AsyncWrite
		/// to hyper's rt::Read/rt::Write traits.
		#[project = TorStreamProj]
		pub enum TorStream {
			Plain { #[pin] inner: TokioIo<DataStream> },
			Tls { #[pin] inner: TokioIo<tokio_openssl::SslStream<DataStream>> },
		}
	}

	impl Read for TorStream {
		fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: ReadBufCursor<'_>) -> Poll<io::Result<()>> {
			match self.project() {
				TorStreamProj::Plain { inner } => inner.poll_read(cx, buf),
				TorStreamProj::Tls { inner } => inner.poll_read(cx, buf),
			}
		}
	}

	impl Write for TorStream {
		fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
			match self.project() {
				TorStreamProj::Plain { inner } => inner.poll_write(cx, buf),
				TorStreamProj::Tls { inner } => inner.poll_write(cx, buf),
			}
		}

		fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			match self.project() {
				TorStreamProj::Plain { inner } => inner.poll_flush(cx),
				TorStreamProj::Tls { inner } => inner.poll_flush(cx),
			}
		}

		fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			match self.project() {
				TorStreamProj::Plain { inner } => inner.poll_shutdown(cx),
				TorStreamProj::Tls { inner } => inner.poll_shutdown(cx),
			}
		}
	}

	impl Connection for TorStream {
		fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
			hyper_util::client::legacy::connect::Connected::new()
		}
	}

	#[derive(Clone)]
	pub struct ArtiConnector {
		tor_client: TorClient<PreferredRuntime>,
		tls_connector: openssl::ssl::SslConnector,
	}

	impl ArtiConnector {
		pub fn new(tor_client: TorClient<PreferredRuntime>) -> Self {
			let mut builder = android_ssl_connector();
			builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
			Self {
				tor_client,
				tls_connector: builder.build(),
			}
		}
	}

	impl tower::Service<Uri> for ArtiConnector {
		type Response = TorStream;
		type Error = Box<dyn std::error::Error + Send + Sync>;
		type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

		fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
			Poll::Ready(Ok(()))
		}

		fn call(&mut self, uri: Uri) -> Self::Future {
			let tor_client = self.tor_client.clone();
			let tls_connector = self.tls_connector.clone();

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

				let is_https = uri.scheme_str() == Some("https");

				if is_https {
					// Wrap with TLS for HTTPS (including .onion HTTPS endpoints)
					let ssl = tls_connector
						.configure()
						.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
						.into_ssl(host)
						.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
					let mut stream = tokio_openssl::SslStream::new(ssl, data_stream)
						.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
					Pin::new(&mut stream)
						.connect()
						.await
						.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
					Ok(TorStream::Tls { inner: TokioIo::new(stream) })
				} else {
					// Plain for HTTP
					Ok(TorStream::Plain { inner: TokioIo::new(data_stream) })
				}
			})
		}
	}
}

#[cfg(feature = "tor")]
use tor_connector::ArtiConnector;

#[cfg(feature = "tor")]
fn build_http_client(tor_client: TorClient<PreferredRuntime>) -> Client<ArtiConnector, Body> {
	let connector = ArtiConnector::new(tor_client);
	Client::builder(TokioExecutor::new()).build::<_, Body>(connector)
}

#[cfg(feature = "tor")]
pub static TOR_CLIENT: LazyLock<ArcSwap<TorClient<PreferredRuntime>>> = LazyLock::new(|| {
	let config = build_tor_config();

	let client = block_on(async {
		info!("Creating and bootstrapping Tor client...");
		match TorClient::with_runtime(PreferredRuntime::current().expect("Could not get runtime"))
			.config(config)
			.create_bootstrapped()
			.await
		{
			Ok(client) => {
				info!("Tor client created and bootstrapped successfully!");
				client
			}
			Err(e) => {
				error!("Failed to create and bootstrap Tor client: {}", e);
				panic!("Cannot start without Tor connection: {}", e);
			}
		}
	});

	ArcSwap::new(Arc::new(client))
});

#[cfg(feature = "tor")]
pub static CLIENT: LazyLock<ArcSwap<Client<ArtiConnector, Body>>> = LazyLock::new(|| {
	let tor_client = (**TOR_CLIENT.load()).clone();
	ArcSwap::new(Arc::new(build_http_client(tor_client)))
});

#[cfg(feature = "tor")]
static TOR_IS_REBUILDING: AtomicBool = AtomicBool::new(false);

/// Rebuild the Tor client and HTTP client when circuits are broken.
/// Uses an atomic flag to prevent concurrent rebuilds.
#[cfg(feature = "tor")]
async fn rebuild_tor_connection() {
	// If already rebuilding, don't start another one
	if TOR_IS_REBUILDING.swap(true, Ordering::SeqCst) {
		info!("Tor circuit rebuild already in progress, skipping");
		return;
	}

	warn!("Rebuilding Tor client due to connection failure...");
	let config = build_tor_config();

	match TorClient::with_runtime(PreferredRuntime::current().expect("Could not get runtime"))
		.config(config)
		.create_bootstrapped()
		.await
	{
		Ok(new_tor) => {
			let new_http = build_http_client(new_tor.clone());
			TOR_CLIENT.store(Arc::new(new_tor));
			CLIENT.store(Arc::new(new_http));
			info!("Tor client rebuilt successfully");
		}
		Err(e) => {
			error!("Failed to rebuild Tor client: {}", e);
		}
	}

	TOR_IS_REBUILDING.store(false, Ordering::SeqCst);
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

async fn stream(url: &str, req: &Request<Body>) -> Result<Response<Body>, String> {
	// First parameter is target URL (mandatory).
	let parsed_uri = url.parse::<Uri>().map_err(|_| "Couldn't parse URL".to_string())?;

	// Build the hyper client from the HTTPS connector or Tor connector.
	let client = CLIENT.load_full();

	let mut builder = Request::get(parsed_uri);

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

	let stream_request = builder.body(empty()).map_err(|_| "Couldn't build empty body in stream".to_string())?;

	client
		.request(stream_request)
		.await
		.map(|res| {
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
		})
		.map_err(|e| e.to_string())
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
			Err(e.to_string())
		}
	}
}

/// Makes a request to Reddit. If `redirect` is `true`, `request_with_redirect`
/// will recurse on the URL that Reddit provides in the Location HTTP header
/// in its response. On Tor, connection failures trigger a circuit rebuild and
/// a single retry.
fn request(method: &'static Method, path: String, redirect: bool, quarantine: bool, base_path: &'static str, host: &'static str) -> Boxed<Result<Response<Body>, String>> {
	async move {
		let result = execute_request(method, &path, redirect, quarantine, base_path, host).await;

		#[cfg(feature = "tor")]
		if result.is_err() {
			warn!("Request to {path} failed over Tor, rebuilding circuit and retrying...");
			rebuild_tor_connection().await;
			return execute_request(method, &path, redirect, quarantine, base_path, host).await;
		}

		result
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
