use crate::{
	config::BackendPolicy,
	oauth_resources::ANDROID_APP_VERSION_LIST,
};
use base64::{engine::general_purpose, Engine as _};
use log::{info, trace, warn};
use serde_json::json;
use std::{fmt, time::Duration};
use tegen::tegen::TextGenerator;
use wreq::{
	header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, HOST, USER_AGENT},
	Client as WreqClient,
};

const REDDIT_ANDROID_OAUTH_CLIENT_ID: &str = "ohXpoqrZYub1kg";
const AUTH_ENDPOINT: &str = "https://www.reddit.com";

#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
	pub fn new(value: String) -> Self {
		Self(value)
	}

	pub fn expose_secret(&self) -> &str {
		&self.0
	}
}

impl fmt::Debug for SecretString {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("[redacted]")
	}
}

#[derive(Clone, Debug)]
pub struct AuthResponse {
	pub token: SecretString,
	pub expires_in: Duration,
	pub additional_headers: HeaderMap,
}

#[derive(Debug)]
pub enum AuthError {
	Transport(wreq::Error),
	Json(serde_json::Error),
	MissingField { field: &'static str, value: serde_json::Value },
	InvalidHeader { name: &'static str },
	InvalidTokenResponse { value: serde_json::Value },
}

impl fmt::Display for AuthError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Transport(err) => write!(f, "transport error: {err}"),
			Self::Json(err) => write!(f, "json error: {err}"),
			Self::MissingField { field, value } => write!(f, "missing token response field {field}: {value}"),
			Self::InvalidHeader { name } => write!(f, "invalid upstream header {name}"),
			Self::InvalidTokenResponse { value } => write!(f, "invalid OAuth token response: {value}"),
		}
	}
}

impl std::error::Error for AuthError {}

impl From<wreq::Error> for AuthError {
	fn from(err: wreq::Error) -> Self {
		Self::Transport(err)
	}
}

impl From<serde_json::Error> for AuthError {
	fn from(err: serde_json::Error) -> Self {
		Self::Json(err)
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BackendKind {
	MobileSpoof,
	GenericWeb,
}

#[derive(Debug, Clone)]
pub enum OAuthBackendImpl {
	MobileSpoof(MobileSpoofAuth),
	GenericWeb(GenericWebAuth),
}

impl OAuthBackendImpl {
	pub fn new_for_policy(policy: BackendPolicy) -> Self {
		match policy {
			BackendPolicy::Auto | BackendPolicy::MobileSpoof => Self::MobileSpoof(MobileSpoofAuth::new()),
			BackendPolicy::GenericWeb => Self::GenericWeb(GenericWebAuth::new()),
		}
	}

	pub fn fallback_for_policy(policy: BackendPolicy) -> Option<Self> {
		match policy {
			BackendPolicy::Auto => Some(Self::GenericWeb(GenericWebAuth::new())),
			BackendPolicy::MobileSpoof | BackendPolicy::GenericWeb => None,
		}
	}

	pub async fn authenticate(&mut self, transport: &WreqClient) -> Result<AuthResponse, AuthError> {
		match self {
			Self::MobileSpoof(backend) => backend.authenticate(transport).await,
			Self::GenericWeb(backend) => backend.authenticate(transport).await,
		}
	}

	pub fn kind(&self) -> BackendKind {
		match self {
			Self::MobileSpoof(_) => BackendKind::MobileSpoof,
			Self::GenericWeb(_) => BackendKind::GenericWeb,
		}
	}

	pub fn user_agent(&self) -> HeaderValue {
		match self {
			Self::MobileSpoof(backend) => backend.user_agent.clone(),
			Self::GenericWeb(backend) => backend.user_agent.clone(),
		}
	}

	pub fn base_headers(&self) -> HeaderMap {
		match self {
			Self::MobileSpoof(backend) => backend.headers.clone(),
			Self::GenericWeb(backend) => backend.headers.clone(),
		}
	}
}

#[derive(Debug, Clone)]
pub struct MobileSpoofAuth {
	oauth_id: String,
	initial_headers: HeaderMap,
	headers: HeaderMap,
	user_agent: HeaderValue,
	additional_headers: HeaderMap,
}

impl MobileSpoofAuth {
	pub fn new() -> Self {
		let uuid = uuid::Uuid::new_v4().to_string();
		let android_app_version = choose(ANDROID_APP_VERSION_LIST);
		let android_version = fastrand::u8(9..=14);
		let user_agent = format!("Reddit/{android_app_version}/Android {android_version}");
		let user_agent_header = HeaderValue::from_str(&user_agent).unwrap_or_else(|_| HeaderValue::from_static("Reddit/Android"));

		let qos = fastrand::u32(1000..=100_000) as f32 / 1000.0;
		let codecs = TextGenerator::new().generate("available-codecs=video/avc, video/hevc{, video/x-vnd.on2.vp9|}");

		let mut headers = HeaderMap::new();
		insert_static(&mut headers, USER_AGENT, user_agent_header.clone());
		insert_static(&mut headers, HeaderName::from_static("x-reddit-retry"), HeaderValue::from_static("algo=no-retries"));
		insert_static(&mut headers, HeaderName::from_static("x-reddit-compression"), HeaderValue::from_static("1"));
		insert_str(&mut headers, HeaderName::from_static("x-reddit-qos"), &format!("{qos:.3}"));
		insert_str(&mut headers, HeaderName::from_static("x-reddit-media-codecs"), &codecs);
		insert_static(&mut headers, CONTENT_TYPE, HeaderValue::from_static("application/json; charset=UTF-8"));
		insert_str(&mut headers, HeaderName::from_static("client-vendor-id"), &uuid);
		insert_str(&mut headers, HeaderName::from_static("x-reddit-device-id"), &uuid);

		info!("[🔄] Creating mobile-spoof Reddit OAuth backend");

		Self {
			oauth_id: REDDIT_ANDROID_OAUTH_CLIENT_ID.to_string(),
			initial_headers: headers.clone(),
			headers,
			user_agent: user_agent_header,
			additional_headers: HeaderMap::new(),
		}
	}

	pub async fn authenticate(&mut self, transport: &WreqClient) -> Result<AuthResponse, AuthError> {
		let url = format!("{AUTH_ENDPOINT}/auth/v2/oauth/access-token/loid");
		let mut builder = transport.post(&url);

		for (key, value) in &self.initial_headers {
			builder = builder.header(key, value);
		}

		let auth = general_purpose::STANDARD.encode(format!("{}:", self.oauth_id));
		builder = builder.header(AUTHORIZATION, format!("Basic {auth}"));

		trace!("Sending mobile-spoof OAuth token request");
		let resp = builder.json(&json!({ "scopes": ["*", "email", "pii"] })).send().await?;

		copy_optional_response_header(resp.headers(), &mut self.additional_headers, "x-reddit-loid");
		copy_optional_response_header(resp.headers(), &mut self.additional_headers, "x-reddit-session");

		let json: serde_json::Value = resp.json().await?;
		let (token, expires_in) = parse_token_json(json)?;

		info!("[✅] Mobile-spoof OAuth authentication succeeded; expires in {expires_in:?}");

		Ok(AuthResponse {
			token,
			expires_in,
			additional_headers: self.additional_headers.clone(),
		})
	}
}

#[derive(Debug, Clone)]
pub struct GenericWebAuth {
	device_id: String,
	user_agent: HeaderValue,
	headers: HeaderMap,
	additional_headers: HeaderMap,
}

impl GenericWebAuth {
	pub fn new() -> Self {
		let device_id: String = (0..20)
			.map(|_| {
				let idx = fastrand::usize(..62);
				let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
				chars[idx] as char
			})
			.collect();

		let user_agent = HeaderValue::from_str(fake_user_agent::get_rua()).unwrap_or_else(|_| HeaderValue::from_static("Mozilla/5.0"));
		let mut headers = HeaderMap::new();
		insert_static(&mut headers, HOST, HeaderValue::from_static("www.reddit.com"));
		insert_static(&mut headers, USER_AGENT, user_agent.clone());
		insert_static(&mut headers, HeaderName::from_static("accept"), HeaderValue::from_static("*/*"));
		insert_static(&mut headers, HeaderName::from_static("accept-language"), HeaderValue::from_static("en-US,en;q=0.5"));
		insert_static(&mut headers, CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
		insert_static(&mut headers, HeaderName::from_static("sec-gpc"), HeaderValue::from_static("1"));
		insert_static(&mut headers, HeaderName::from_static("connection"), HeaderValue::from_static("keep-alive"));
		insert_static(&mut headers, HeaderName::from_static("origin"), HeaderValue::from_static("https://www.reddit.com"));

		info!("[🔄] Creating generic-web Reddit OAuth backend");

		Self {
			device_id,
			user_agent,
			headers,
			additional_headers: HeaderMap::new(),
		}
	}

	pub async fn authenticate(&mut self, transport: &WreqClient) -> Result<AuthResponse, AuthError> {
		let url = "https://www.reddit.com/api/v1/access_token";
		let body = format!(
			"grant_type=https%3A%2F%2Foauth.reddit.com%2Fgrants%2Finstalled_client&device_id={}",
			self.device_id
		);

		let mut builder = transport.post(url);
		for (key, value) in &self.headers {
			builder = builder.header(key, value);
		}
		builder = builder.header(AUTHORIZATION, HeaderValue::from_static("Basic M1hmQkpXbGlIdnFBQ25YcmZJWWxMdzo="));

		trace!("Sending generic-web OAuth token request");
		let resp = builder.body(body).send().await?;

		copy_optional_response_header(resp.headers(), &mut self.additional_headers, "x-reddit-loid");
		copy_optional_response_header(resp.headers(), &mut self.additional_headers, "x-reddit-session");

		let json: serde_json::Value = resp.json().await?;
		let (token, expires_in) = parse_token_json(json)?;

		info!("[✅] Generic-web OAuth authentication succeeded; expires in {expires_in:?}");

		Ok(AuthResponse {
			token,
			expires_in,
			additional_headers: self.additional_headers.clone(),
		})
	}
}

fn parse_token_json(json: serde_json::Value) -> Result<(SecretString, Duration), AuthError> {
	let token = json
		.get("access_token")
		.ok_or_else(|| AuthError::MissingField {
			field: "access_token",
			value: json.clone(),
		})?
		.as_str()
		.ok_or_else(|| AuthError::InvalidTokenResponse { value: json.clone() })?
		.to_string();

	let expires_in = json
		.get("expires_in")
		.ok_or_else(|| AuthError::MissingField {
			field: "expires_in",
			value: json.clone(),
		})?
		.as_u64()
		.ok_or_else(|| AuthError::InvalidTokenResponse { value: json })?;

	Ok((SecretString::new(token), Duration::from_secs(expires_in)))
}

fn copy_optional_response_header(source: &HeaderMap, target: &mut HeaderMap, name: &'static str) {
	let header_name = HeaderName::from_static(name);
	if let Some(value) = source.get(&header_name) {
		target.insert(header_name, value.clone());
	}
}

fn insert_static(headers: &mut HeaderMap, name: HeaderName, value: HeaderValue) {
	headers.insert(name, value);
}

fn insert_str(headers: &mut HeaderMap, name: HeaderName, value: &str) {
	match HeaderValue::from_str(value) {
		Ok(value) => {
			headers.insert(name, value);
		}
		Err(_) => warn!("skipping invalid generated OAuth header {}", name),
	}
}

fn choose<T: Copy>(list: &[T]) -> T {
	list[fastrand::usize(..list.len())]
}
