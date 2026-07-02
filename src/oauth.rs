use std::{collections::HashMap, sync::atomic::Ordering, time::Duration};

use crate::{
	body::full,
	oauth_resources::ANDROID_APP_VERSION_LIST,
};
use std::sync::Arc;
#[cfg(feature = "tor")]
use crate::client::{mark_tor_connection_healthy, recover_tor_connection};
use base64::{engine::general_purpose, Engine as _};
use hyper::{Method, Request};
use http_body_util::BodyExt;
use log::{error, info, trace, warn};
use serde_json::json;
use tegen::tegen::TextGenerator;
use tokio::time::{error::Elapsed, timeout};

const REDDIT_ANDROID_OAUTH_CLIENT_ID: &str = "ohXpoqrZYub1kg";

#[cfg(not(feature = "tor"))]
const AUTH_ENDPOINT: &str = "https://www.reddit.com";
#[cfg(feature = "tor")]
const AUTH_ENDPOINT: &str = "https://www.reddittorjg6rue252oqsxryoxengawnmo46qy4kyii5wtqnwfj4ooad.onion";

const OAUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const OAUTH_RETRY_DELAY: Duration = Duration::from_secs(5);

// Response from OAuth backend authentication
#[derive(Debug, Clone)]
pub struct OauthResponse {
	pub token: String,
	pub expires_in: u64,
	pub additional_headers: HashMap<String, String>,
}

// Trait for OAuth backend implementations
trait OauthBackend: Send + Sync {
	fn authenticate(&mut self, http_client: Arc<crate::client::HttpClient>) -> impl std::future::Future<Output = Result<OauthResponse, AuthError>> + Send;
	fn user_agent(&self) -> &str;
	fn get_headers(&self) -> HashMap<String, String>;
}

// OAuth backend implementations
#[derive(Debug, Clone)]
pub(crate) enum OauthBackendImpl {
	MobileSpoof(MobileSpoofAuth),
	GenericWeb(GenericWebAuth),
}

impl OauthBackend for OauthBackendImpl {
	async fn authenticate(&mut self, http_client: Arc<crate::client::HttpClient>) -> Result<OauthResponse, AuthError> {
		match self {
			OauthBackendImpl::MobileSpoof(backend) => backend.authenticate(http_client).await,
			OauthBackendImpl::GenericWeb(backend) => backend.authenticate(http_client).await,
		}
	}

	fn user_agent(&self) -> &str {
		match self {
			OauthBackendImpl::MobileSpoof(backend) => backend.user_agent(),
			OauthBackendImpl::GenericWeb(backend) => backend.user_agent(),
		}
	}

	fn get_headers(&self) -> HashMap<String, String> {
		match self {
			OauthBackendImpl::MobileSpoof(backend) => backend.get_headers(),
			OauthBackendImpl::GenericWeb(backend) => backend.get_headers(),
		}
	}
}

// Spoofed client for Android devices
#[derive(Debug, Clone)]
pub struct Oauth {
	pub(crate) headers_map: HashMap<String, String>,
	pub(crate) expires_at: i64,
	pub(crate) backend: OauthBackendImpl,
}

impl Oauth {
	/// Create a new OAuth client
	pub(crate) async fn new(http_client: &crate::client::HttpClient) -> Self {
		// Try MobileSpoofAuth first, then fall back to GenericWebAuth
		let mut failure_count = 0;
		let mut backend = OauthBackendImpl::MobileSpoof(MobileSpoofAuth::new());

		loop {
			let attempt = Self::new_with_timeout_with_backend(backend.clone(), http_client.clone()).await;
			match attempt {
				Ok(Ok(oauth)) => {
					#[cfg(feature = "tor")]
					mark_tor_connection_healthy();
					info!("[✅] Successfully created OAuth client");
					return oauth;
				}
				Ok(Err(e)) => {
					let err_msg = match e {
						AuthError::Hyper(error) => error,
						AuthError::SerdeDeserialize(error) => error.to_string(),
						AuthError::Field((value, error)) => format!("{error}\n{value}"),
					};
					error!(
						"[⛔] Failed to create OAuth client: {}. Retrying in 5 seconds...",
						err_msg
					);
					#[cfg(feature = "tor")]
					{
						recover_tor_connection("OAuth client creation", Some(err_msg.as_str())).await;
					}
				}
				Err(_) => {
					error!("[⛔] Failed to create OAuth client before timeout. Retrying in 5 seconds...");
					#[cfg(feature = "tor")]
					{
						recover_tor_connection("OAuth client creation", None).await;
					}
				}
			}

			failure_count += 1;

			// Switch to GenericWeb after 5 failures with MobileSpoof
			if matches!(backend, OauthBackendImpl::MobileSpoof(_)) && failure_count >= 5 {
				warn!("[🔄] MobileSpoofAuth failed 5 times. Falling back to GenericWebAuth...");
				backend = OauthBackendImpl::GenericWeb(GenericWebAuth::new());
			}

			// Never kill the process here: keep retrying and let Tor recovery logic rotate state if needed.
			if failure_count >= 10 {
				error!("[⛔] Failed to create OAuth client (mobile + generic). Continuing recovery retries...");
				failure_count = 0;
				backend = OauthBackendImpl::MobileSpoof(MobileSpoofAuth::new());
			}

			tokio::time::sleep(OAUTH_RETRY_DELAY).await;
		}
	}

	async fn new_with_timeout_with_backend(mut backend: OauthBackendImpl, http_client: crate::client::HttpClient) -> Result<Result<Self, AuthError>, Elapsed> {
		timeout(OAUTH_REQUEST_TIMEOUT, async move {
			let response = backend.authenticate(Arc::new(http_client)).await?;

			// Build headers_map from backend headers + Authorization header
			let mut headers_map = backend.get_headers();
			headers_map.insert("Authorization".to_owned(), format!("Bearer {}", response.token));
			headers_map.extend(response.additional_headers);

			Ok(Self {
				headers_map,
				expires_at: time::OffsetDateTime::now_utc().unix_timestamp() + (response.expires_in as i64),
				backend,
			})
		})
		.await
	}

	pub fn user_agent(&self) -> &str {
		self.backend.user_agent()
	}
}

#[derive(Debug)]
enum AuthError {
	Hyper(String),
	SerdeDeserialize(serde_json::Error),
	Field((serde_json::Value, &'static str)),
}

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

impl From<hyper_util::client::legacy::Error> for AuthError {
	fn from(err: hyper_util::client::legacy::Error) -> Self {
		AuthError::Hyper(format_client_connect_error(&err))
	}
}

impl From<serde_json::Error> for AuthError {
	fn from(err: serde_json::Error) -> Self {
		AuthError::SerdeDeserialize(err)
	}
}

pub async fn token_daemon() {
	// Monitor for refreshing tokens across the session pool
	loop {
		let now = time::OffsetDateTime::now_utc().unix_timestamp();
		let mut min_expires_at = i64::MAX;

		for session in crate::client::SESSION_POOL.iter() {
			let expires_at = session.oauth.load().expires_at;
			if expires_at < min_expires_at {
				min_expires_at = expires_at;
			}
		}

		let sleep_until = min_expires_at.saturating_sub(120);
		// Give it at least 5 seconds before checking again to avoid spin-locking if something goes wrong
		let sleep_duration = sleep_until.saturating_sub(now).max(5);

		let duration = Duration::from_secs(sleep_duration as u64);

		info!("[⏳] Waiting for {duration:?} seconds before refreshing nearest expiring OAuth token in pool...");
		tokio::time::sleep(duration).await;
		info!("[⌛] {duration:?} Elapsed! Initiating targeted token refresh sweeps...");

		let now_after = time::OffsetDateTime::now_utc().unix_timestamp();
		for session in crate::client::SESSION_POOL.iter() {
			if session.oauth.load().expires_at.saturating_sub(now_after) <= 120 {
				let s = session.clone();
				tokio::spawn(async move {
					force_refresh_token(s).await;
				});
			}
		}
	}
}

pub async fn force_refresh_token(session: Arc<crate::client::Session>) {
	if session.is_rolling_over.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
		trace!("Skipping refresh token roll over, already in progress for this session");
		return;
	}

	trace!("Rolling over refresh token. Current session rate limit: {}", session.ratelimit_remaining.load(Ordering::SeqCst));
	let http_client = session.http_client.load_full();
	let new_oauth = Oauth::new(&http_client).await;
	session.oauth.store(Arc::new(new_oauth));
	session.ratelimit_remaining.store(99, Ordering::SeqCst);
	session.is_rolling_over.store(false, Ordering::SeqCst);
}

#[derive(Debug, Clone, Default)]
struct Device {
	oauth_id: String,
	initial_headers: HashMap<String, String>,
	headers: HashMap<String, String>,
	user_agent: String,
}

// MobileSpoofAuth backend - spoofs an Android mobile device
#[derive(Debug, Clone)]
pub struct MobileSpoofAuth {
	device: Device,
	additional_headers: HashMap<String, String>,
}

impl MobileSpoofAuth {
	fn new() -> Self {
		Self {
			device: Device::new(),
			additional_headers: HashMap::new(),
		}
	}
}

impl OauthBackend for MobileSpoofAuth {
	async fn authenticate(&mut self, http_client: Arc<crate::client::HttpClient>) -> Result<OauthResponse, AuthError> {
		// Construct URL for OAuth token
		let url = format!("{AUTH_ENDPOINT}/auth/v2/oauth/access-token/loid");
		let mut builder = Request::builder().method(Method::POST).uri(&url);

		// Add headers from spoofed client
		for (key, value) in &self.device.initial_headers {
			builder = builder.header(key, value);
		}
		// Set up HTTP Basic Auth - basically just the const OAuth ID's with no password,
		// Base64-encoded. https://en.wikipedia.org/wiki/Basic_access_authentication
		// This could be constant, but I don't think it's worth it. OAuth ID's can change
		// over time and we want to be flexible.
		let auth = general_purpose::STANDARD.encode(format!("{}:", self.device.oauth_id));
		builder = builder.header("Authorization", format!("Basic {auth}"));

		// Set JSON body. I couldn't tell you what this means. But that's what the client sends
		let json = json!({
				"scopes": ["*","email", "pii"]
		});
		let body = full(json.to_string());

		// Build request
		let request = builder.body(body).unwrap();

		trace!("Sending token request...\n\n{request:?}");

		// Send request using the isolated HTTP client
		let resp = http_client.request(request).await?;

		trace!("Received response with status {} and length {:?}", resp.status(), resp.headers().get("content-length"));
		trace!("OAuth headers: {:#?}", resp.headers());

		// Parse headers - loid header _should_ be saved sent on subsequent token refreshes.
		// Technically it's not needed, but it's easy for Reddit API to check for this.
		// It's some kind of header that uniquely identifies the device.
		// Not worried about the privacy implications, since this is randomly changed
		// and really only as privacy-concerning as the OAuth token itself.
		if let Some(header) = resp.headers().get("x-reddit-loid") {
			self.additional_headers.insert("x-reddit-loid".to_owned(), header.to_str().unwrap().to_string());
		}

		// Same with x-reddit-session
		if let Some(header) = resp.headers().get("x-reddit-session") {
			self.additional_headers.insert("x-reddit-session".to_owned(), header.to_str().unwrap().to_string());
		}

		trace!("Serializing response...");

		// Serialize response
		let body_bytes = resp.into_body().collect().await.map_err(|e| AuthError::Hyper(e.to_string()))?.to_bytes();
		let json: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(AuthError::SerdeDeserialize)?;

		trace!("Accessing relevant fields...");

		// Save token and expiry
		let token = json
			.get("access_token")
			.ok_or_else(|| AuthError::Field((json.clone(), "access_token")))?
			.as_str()
			.ok_or_else(|| AuthError::Field((json.clone(), "access_token: as_str")))?
			.to_string();
		let expires_in = json
			.get("expires_in")
			.ok_or_else(|| AuthError::Field((json.clone(), "expires_in")))?
			.as_u64()
			.ok_or_else(|| AuthError::Field((json.clone(), "expires_in: as_u64")))?;

		info!("[✅] Success - Retrieved token \"{}...\", expires in {}", &token[..32], expires_in);

		Ok(OauthResponse {
			token,
			expires_in,
			additional_headers: self.additional_headers.clone(),
		})
	}

	fn user_agent(&self) -> &str {
		&self.device.user_agent
	}

	fn get_headers(&self) -> HashMap<String, String> {
		let mut headers = self.device.headers.clone();
		headers.extend(self.additional_headers.clone());
		headers
	}
}

// GenericWebAuth backend - simple web-based authentication
#[derive(Debug, Clone)]
pub struct GenericWebAuth {
	device_id: String,
	user_agent: String,
	additional_headers: HashMap<String, String>,
}

impl GenericWebAuth {
	fn new() -> Self {
		// Generate random 20-character alphanumeric device_id
		let device_id: String = (0..20)
			.map(|_| {
				let idx = fastrand::usize(..62);
				let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
				chars[idx] as char
			})
			.collect();

		info!("[🔄] Using GenericWebAuth with device_id: \"{device_id}\"");

		Self {
			device_id,
			user_agent: fake_user_agent::get_rua().to_owned(),
			additional_headers: HashMap::new(),
		}
	}
}

impl OauthBackend for GenericWebAuth {
	async fn authenticate(&mut self, http_client: Arc<crate::client::HttpClient>) -> Result<OauthResponse, AuthError> {
		// Construct URL for OAuth token
		let url = "https://www.reddit.com/api/v1/access_token";
		let mut builder = Request::builder().method(Method::POST).uri(url);

		// Add minimal headers
		builder = builder.header("Host", "www.reddit.com");
		builder = builder.header("User-Agent", &self.user_agent);
		builder = builder.header("Accept", "*/*");
		builder = builder.header("Accept-Language", "en-US,en;q=0.5");
		// builder = builder.header("Accept-Encoding", "gzip, deflate, br, zstd");
		builder = builder.header("Authorization", "Basic M1hmQkpXbGlIdnFBQ25YcmZJWWxMdzo=");
		builder = builder.header("Content-Type", "application/x-www-form-urlencoded");
		builder = builder.header("Sec-GPC", "1");
		builder = builder.header("Connection", "keep-alive");

		// Set up form body
		let body_str = format!("grant_type=https%3A%2F%2Foauth.reddit.com%2Fgrants%2Finstalled_client&device_id={}", self.device_id);
		let body = full(body_str);

		// Build request
		let request = builder.body(body).unwrap();

		trace!("Sending GenericWebAuth token request...\n\n{request:?}");

		// Send request using isolated HTTP client
		let resp = http_client.request(request).await?;

		trace!("Received response with status {} and length {:?}", resp.status(), resp.headers().get("content-length"));
		trace!("GenericWebAuth headers: {:#?}", resp.headers());

		// Parse headers - loid header _should_ be saved sent on subsequent token refreshes.
		// Technically it's not needed, but it's easy for Reddit API to check for this.
		// It's some kind of header that uniquely identifies the device.
		// Not worried about the privacy implications, since this is randomly changed
		// and really only as privacy-concerning as the OAuth token itself.
		if let Some(header) = resp.headers().get("x-reddit-loid") {
			self.additional_headers.insert("x-reddit-loid".to_owned(), header.to_str().unwrap().to_string());
		}

		// Same with x-reddit-session
		if let Some(header) = resp.headers().get("x-reddit-session") {
			self.additional_headers.insert("x-reddit-session".to_owned(), header.to_str().unwrap().to_string());
		}

		trace!("Serializing GenericWebAuth response...");

		// Serialize response
		let body_bytes = resp.into_body().collect().await.map_err(|e| AuthError::Hyper(e.to_string()))?.to_bytes();
		let json: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(AuthError::SerdeDeserialize)?;

		trace!("Accessing relevant fields...");

		// Parse response - access_token, token_type, device_id, expires_in, scope
		let token = json
			.get("access_token")
			.ok_or_else(|| AuthError::Field((json.clone(), "access_token")))?
			.as_str()
			.ok_or_else(|| AuthError::Field((json.clone(), "access_token: as_str")))?
			.to_string();
		let expires_in = json
			.get("expires_in")
			.ok_or_else(|| AuthError::Field((json.clone(), "expires_in")))?
			.as_u64()
			.ok_or_else(|| AuthError::Field((json.clone(), "expires_in: as_u64")))?;

		info!(
			"[✅] GenericWebAuth success - Retrieved token \"{}...\", expires in {}",
			&token[..32.min(token.len())],
			expires_in
		);

		// Insert a few necessary headers
		self.additional_headers.insert("Origin".to_owned(), "https://www.reddit.com".to_owned());
		self.additional_headers.insert("User-Agent".to_owned(), self.user_agent.to_owned());

		Ok(OauthResponse {
			token,
			expires_in,
			additional_headers: self.additional_headers.clone(),
		})
	}

	fn user_agent(&self) -> &str {
		&self.user_agent
	}

	fn get_headers(&self) -> HashMap<String, String> {
		self.additional_headers.clone()
	}
}

impl Device {
	fn android() -> Self {
		// Generate uuid
		let uuid = uuid::Uuid::new_v4().to_string();

		// Generate random user-agent
		let android_app_version = choose(ANDROID_APP_VERSION_LIST).to_string();
		let android_version = fastrand::u8(9..=16);

		let android_user_agent = format!("Reddit/{android_app_version}/Android {android_version}");

		let qos = fastrand::u32(1000..=100_000);
		let qos: f32 = qos as f32 / 1000.0;
		let qos = format!("{qos:.3}");

		let codecs = TextGenerator::new().generate("available-codecs=video/avc, video/hevc{, video/x-vnd.on2.vp9|}");

		// Android device headers
		let headers: HashMap<String, String> = HashMap::from([
			("User-Agent".into(), android_user_agent.clone()),
			("x-reddit-retry".into(), "algo=no-retries".into()),
			("x-reddit-compression".into(), "1".into()),
			("x-reddit-qos".into(), qos),
			("x-reddit-media-codecs".into(), codecs),
			("Content-Type".into(), "application/json; charset=UTF-8".into()),
			("client-vendor-id".into(), uuid.clone()),
			("X-Reddit-Device-Id".into(), uuid.clone()),
		]);

		info!("[🔄] Spoofing Android client with headers: {headers:?}, uuid: \"{uuid}\", and OAuth ID \"{REDDIT_ANDROID_OAUTH_CLIENT_ID}\"");

		Self {
			oauth_id: REDDIT_ANDROID_OAUTH_CLIENT_ID.to_string(),
			headers: headers.clone(),
			initial_headers: headers,
			user_agent: android_user_agent,
		}
	}
	fn new() -> Self {
		// See https://github.com/redlib-org/redlib/issues/8
		Self::android()
	}
}

fn choose<T: Copy>(list: &[T]) -> T {
	*fastrand::choose_multiple(list.iter(), 1)[0]
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mobile_spoof_backend() {
	// Test MobileSpoofAuth backend specifically
	let mut backend = MobileSpoofAuth::new();
	let http_client = Arc::new(crate::client::create_http_client());
	let response = backend.authenticate(http_client).await;
	assert!(response.is_ok());
	let response = response.unwrap();
	assert!(!response.token.is_empty());
	assert!(response.expires_in > 0);
	assert!(!backend.user_agent().is_empty());
	assert!(!backend.get_headers().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_generic_web_backend() {
	// Test GenericWebAuth backend specifically
	let mut backend = GenericWebAuth::new();
	let http_client = Arc::new(crate::client::create_http_client());
	let response = backend.authenticate(http_client).await;
	assert!(response.is_ok());
	let response = response.unwrap();
	assert!(!response.token.is_empty());
	assert!(response.expires_in > 0);
	assert!(!backend.user_agent().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_oauth_client() {
	// Integration test - tests the overall Oauth client
    let session = crate::client::SESSION_POOL[0].clone();
	assert!(session.oauth.load_full().headers_map.contains_key("Authorization"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_oauth_client_refresh() {
    let session = crate::client::SESSION_POOL[0].clone();
	force_refresh_token(session).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_oauth_token_exists() {
    let session = crate::client::SESSION_POOL[0].clone();
	let oauth = session.oauth.load_full();
	let auth_header = oauth.headers_map.get("Authorization").unwrap();
	assert!(auth_header.starts_with("Bearer "));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_oauth_headers_len() {
    let session = crate::client::SESSION_POOL[0].clone();
	assert!(session.oauth.load_full().headers_map.len() >= 3);
}

#[test]
fn test_creating_device() {
	Device::new();
}

#[test]
fn test_creating_backends() {
	// Test that both backends can be created
	MobileSpoofAuth::new();
	GenericWebAuth::new();
}
