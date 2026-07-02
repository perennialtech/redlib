use crate::{
	config::RedditConfig,
	reddit::{
		pool::OAuthSessionPool,
		request::{ApiError, ApiErrorKind, RateCost, RedditBase, RedditRequest, RedditResponse, RetryPolicy},
		session::{SessionId, SessionLease},
		transport::build_media_http_client,
	},
	server::RequestExt,
	utils::format_url,
};
use hyper::{header, Body, Request as HyperRequest, Response as HyperResponse};
use log::trace;
use percent_encoding::{percent_encode, CONTROLS};
use serde_json::Value;
use std::{
	collections::{HashMap, HashSet},
	hash::Hash,
	num::NonZeroUsize,
	sync::Arc,
	time::{Duration, Instant},
};
use tokio::{
	sync::{oneshot, Mutex},
	time::timeout,
};
use wreq::{
	header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, COOKIE, HOST, LOCATION, USER_AGENT},
	Client as WreqClient, Method, Response as WreqResponse,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct JsonCacheKey {
	path: String,
	quarantine: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct CanonicalCacheKey {
	path: String,
	tries: u8,
}


pub struct RedditGateway {
	pool: Arc<OAuthSessionPool>,
	json_cache: Mutex<HashMap<JsonCacheKey, (Instant, Value)>>,
	json_waiters: Mutex<HashMap<JsonCacheKey, Vec<oneshot::Sender<Result<Value, ApiError>>>>>,
	canonical_cache: Mutex<HashMap<CanonicalCacheKey, (Instant, Option<String>)>>,
	canonical_waiters: Mutex<HashMap<CanonicalCacheKey, Vec<oneshot::Sender<Result<Option<String>, ApiError>>>>>,
	media_http: WreqClient,
	config: RedditConfig,
}

impl RedditGateway {
	pub async fn new(config: RedditConfig) -> Result<Self, ApiError> {
		let pool = OAuthSessionPool::bootstrap(config.clone()).await?;

		Ok(Self {
			pool,
			json_cache: Mutex::new(HashMap::new()),
			json_waiters: Mutex::new(HashMap::new()),
			canonical_cache: Mutex::new(HashMap::new()),
			canonical_waiters: Mutex::new(HashMap::new()),
			media_http: build_media_http_client(),
			config,
		})
	}

	pub fn pool(&self) -> Arc<OAuthSessionPool> {
		self.pool.clone()
	}

	pub async fn json(&self, path: String, quarantine: bool) -> Result<Value, ApiError> {
		let key = JsonCacheKey {
			path: path.clone(),
			quarantine,
		};

		if let Some(value) = self.get_json_cache(&key).await {
			return Ok(value);
		}

		if let Some(rx) = self.join_json_wait(&key).await {
			return rx.await.unwrap_or_else(|_| {
				Err(ApiError::new(
					500,
					ApiErrorKind::InvalidResponse,
					"coalesced Reddit JSON request was cancelled",
				))
			});
		}

		let result = self.json_uncached(path, quarantine).await;
		if let Ok(value) = &result {
			self.json_cache
				.lock()
				.await
				.insert(key.clone(), (Instant::now() + Duration::from_secs(30), value.clone()));
		}
		self.finish_json_wait(&key, result.clone()).await;
		result
	}

	async fn json_uncached(&self, path: String, quarantine: bool) -> Result<Value, ApiError> {
		let response = self
			.send(RedditRequest {
				method: Method::GET,
				base: RedditBase::OAuth,
				path: path.clone(),
				quarantine,
				follow_redirects: true,
				cost: RateCost::ONE,
				retry_policy: self.default_retry_policy(),
			})
			.await?;

		let status = response.status;

		if response.body.is_empty() {
			return Err(ApiError::new(
				429,
				ApiErrorKind::RateLimited,
				"Reddit rate limit exceeded",
			));
		}

		let json: Value = serde_json::from_slice(&response.body).map_err(|err| {
			if status.is_server_error() {
				ApiError::new(status.as_u16(), ApiErrorKind::InvalidResponse, "Reddit is having issues, check if there's an outage")
			} else {
				ApiError::new(
					status.as_u16(),
					ApiErrorKind::RedditJson,
					format!("Failed to parse page JSON data: {err} | {path}"),
				)
			}
		})?;

		if let Some(data) = json.get("data") {
			if data.get("is_suspended").and_then(Value::as_bool) == Some(true) {
				return Err(ApiError::new(404, ApiErrorKind::RedditStatus, "suspended"));
			}
		}

		if json["error"].is_i64() {
			if json["message"] == "Unauthorized" {
				return Err(ApiError::new(401, ApiErrorKind::Auth, "OAuth token has expired. Please refresh the page!"));
			}
			if json["reason"] == "quarantined" {
				return Err(ApiError::new(403, ApiErrorKind::RedditStatus, "quarantined"));
			}
			if json["reason"] == "gated" {
				return Err(ApiError::new(403, ApiErrorKind::RedditStatus, "gated"));
			}
			if json["reason"] == "private" {
				return Err(ApiError::new(403, ApiErrorKind::RedditStatus, "private"));
			}
			if json["reason"] == "banned" {
				return Err(ApiError::new(404, ApiErrorKind::RedditStatus, "banned"));
			}

			let json_err_status = json["error"].as_i64().unwrap_or(500) as u16;
			return Err(ApiError::new(
				json_err_status,
				ApiErrorKind::RedditStatus,
				format!("Reddit error {} \"{}\": {} | {path}", json["error"], json["reason"], json["message"]),
			));
		}

		Ok(json)
	}

	pub async fn canonical_path(&self, path: String, tries: u8) -> Result<Option<String>, ApiError> {
		if tries == 0 {
			return Ok(None);
		}

		let key = CanonicalCacheKey {
			path: path.clone(),
			tries,
		};

		if let Some(value) = self.get_canonical_cache(&key).await {
			return Ok(value);
		}

		if let Some(rx) = self.join_canonical_wait(&key).await {
			return rx.await.unwrap_or_else(|_| Ok(None));
		}

		let result = self.canonical_path_uncached(path, tries).await;
		if let Ok(value) = &result {
			self.canonical_cache
				.lock()
				.await
				.insert(key.clone(), (Instant::now() + Duration::from_secs(600), value.clone()));
		}
		self.finish_canonical_wait(&key, result.clone()).await;
		result
	}

	async fn canonical_path_uncached(&self, path: String, tries: u8) -> Result<Option<String>, ApiError> {
		let mut last_error = None;

		for base in [RedditBase::Alternative, RedditBase::Short] {
			let response = self
				.send(RedditRequest {
					method: Method::HEAD,
					base,
					path: path.clone(),
					quarantine: true,
					follow_redirects: false,
					cost: RateCost::ONE,
					retry_policy: self.default_retry_policy(),
				})
				.await;

			match response {
				Ok(response) if !response.status.is_client_error() => return self.classify_canonical_response(path, tries, response).await,
				Ok(response) => last_error = Some(ApiError::new(response.status.as_u16(), ApiErrorKind::RedditStatus, "canonical HEAD request failed")),
				Err(err) => last_error = Some(err),
			}
		}

		Err(last_error.unwrap_or_else(|| ApiError::new(500, ApiErrorKind::Transport, "Unable to make HEAD request to Reddit.")))
	}

	async fn classify_canonical_response(&self, path: String, tries: u8, response: RedditResponse) -> Result<Option<String>, ApiError> {
		let status = response.status.as_u16();
		let policy_error = response.headers.get("retry-after").is_some();

		match status {
			200..=299 => Ok(Some(path)),
			301 => match response.headers.get(LOCATION) {
				Some(val) => {
					let original = val
						.to_str()
						.map_err(|_| ApiError::new(500, ApiErrorKind::InvalidRedirect, "Unable to decode Location header."))?;
					let stripped_uri = original.strip_suffix(".json").unwrap_or(original).split('?').next().unwrap_or_default();
					let uri = format_url(stripped_uri);
					Box::pin(self.canonical_path(uri, tries - 1)).await
				}
				None => Ok(None),
			},
			300..=399 => Ok(None),
			429 => Err(ApiError::new(429, ApiErrorKind::RateLimited, "Too many requests.")),
			403 if policy_error => Err(ApiError::new(429, ApiErrorKind::RateLimited, "Too many requests.")),
			_ => Ok(response.headers.get(LOCATION).map(|val| {
				percent_encode(val.as_bytes(), CONTROLS)
					.to_string()
					.trim_start_matches(RedditBase::OAuth.url())
					.to_string()
			})),
		}
	}

	pub async fn send(&self, request: RedditRequest) -> Result<RedditResponse, ApiError> {
		let mut excluded = HashSet::<SessionId>::new();
		let attempts = request.retry_policy.max_attempts.get().max(1);

		for attempt in 0..attempts {
			let lease = self.pool.acquire(&excluded, request.cost).await?;
			match self.send_with_lease(&request, &lease).await {
				Ok(response) if response.status.as_u16() == 401 && attempt + 1 < attempts => {
					let session = lease.session.clone();
					excluded.insert(session.id);
					tokio::spawn(async move {
						let _ = session.refresh_token().await;
					});
					continue;
				}
				Ok(response) if is_rate_limited(&response) && attempt + 1 < attempts => {
					lease.session.apply_quota_policy().await;
					excluded.insert(lease.session.id);
					continue;
				}
				Ok(response) => return Ok(response),
				Err(err) if matches!(err.kind, ApiErrorKind::Transport) && attempt + 1 < attempts => {
					lease.session.mark_transport_failure().await;
					excluded.insert(lease.session.id);
					continue;
				}
				Err(err) => return Err(err),
			}
		}

		self.pool.acquire(&excluded, request.cost).await.map(|_| unreachable!()).map_err(|err| err)
	}

	async fn send_with_lease(&self, request: &RedditRequest, lease: &SessionLease) -> Result<RedditResponse, ApiError> {
		let mut current_path = request.path.clone();

		for _redirect in 0..8 {
			lease.session.reserve_cost(request.cost).await;

			let url = format!("{}{}", request.base.url(), current_path);
			let mut builder = lease.session.transport.request(request.method.clone(), &url);

			let mut headers = Vec::<(HeaderName, HeaderValue)>::new();
			headers.push((HOST, HeaderValue::from_static(request.base.host())));
			if request.quarantine {
				headers.push((
					COOKIE,
					HeaderValue::from_static("_options=%7B%22pref_quarantine_optin%22%3A%20true%2C%20%22pref_gated_sr_optin%22%3A%20true%7D"),
				));
			}
			for (name, value) in lease.token.auth_headers.iter() {
				headers.push((name.clone(), value.clone()));
			}

			fastrand::shuffle(&mut headers);
			for (name, value) in headers {
				builder = builder.header(name, value);
			}

			trace!("Sending Reddit API request via session {}", lease.session.id);

			let resp = timeout(self.config.request_timeout, builder.send())
				.await
				.map_err(|_| ApiError::new(504, ApiErrorKind::Transport, "Reddit API request timed out"))?
				.map_err(|err| ApiError::new(502, ApiErrorKind::Transport, format!("Couldn't send request to Reddit: {err}")))?;

			lease.session.update_rate_limit(resp.headers(), resp.status()).await;

			if resp.status().is_redirection() && request.follow_redirects {
				let Some(location) = resp.headers().get(LOCATION).and_then(|header| header.to_str().ok()) else {
					return Err(ApiError::new(502, ApiErrorKind::InvalidRedirect, "Reddit response was missing a Location header"));
				};
				if location == RedditBase::Alternative.url() {
					return Err(ApiError::new(502, ApiErrorKind::InvalidRedirect, "Reddit response was invalid"));
				}

				let new_path = percent_encode(location.as_bytes(), CONTROLS)
					.to_string()
					.trim_start_matches(RedditBase::OAuth.url())
					.trim_start_matches(RedditBase::Alternative.url())
					.to_string();
				current_path = format!("{new_path}{}raw_json=1", if new_path.contains('?') { "&" } else { "?" });
				continue;
			}

			let status = resp.status();
			let headers = resp.headers().clone();
			let body = resp.bytes().await.map_err(|err| ApiError::new(502, ApiErrorKind::InvalidResponse, format!("Failed receiving body from Reddit: {err}")))?;
			return Ok(RedditResponse {
				status,
				headers,
				body: body.to_vec(),
			});
		}

		Err(ApiError::new(508, ApiErrorKind::InvalidRedirect, "Reddit redirect chain was too long"))
	}

	pub async fn proxy_media(&self, req: HyperRequest<Body>, format: &str) -> Result<HyperResponse<Body>, String> {
		let mut url = format!("{format}?{}", req.uri().query().unwrap_or_default());

		for (name, value) in &req.params() {
			url = url.replace(&format!("{{{name}}}"), value);
		}

		let wreq_uri = wreq::Uri::try_from(url).map_err(|_| "Couldn't parse URL".to_string())?;
		let mut builder = self.media_http.get(wreq_uri);

		for &key in &["Range", "If-Modified-Since", "Cache-Control"] {
			if let Some(value) = req.headers().get(key) {
				builder = builder.header(key, value.as_bytes());
			}
		}

		if let Some(user_agent) = self.media_user_agent().await {
			builder = builder.header(USER_AGENT, user_agent);
		}
		builder = builder.header(ACCEPT, "*/*");

		builder
			.send()
			.await
			.map(|mut res| {
				let headers = res.headers_mut();
				for key in [
					"access-control-expose-headers",
					"server",
					"vary",
					"etag",
					"x-cdn",
					"x-cdn-client-region",
					"x-cdn-name",
					"x-cdn-server-region",
					"x-reddit-cdn",
					"x-reddit-video-features",
					"Nel",
					"Report-To",
				] {
					headers.remove(key);
				}
				into_hyper_response(res)
			})
			.map_err(|e| e.to_string())
	}

	pub async fn health_check(&self, deep: bool) -> Result<(), ApiError> {
		let snapshot = self.pool.snapshot().await;
		if snapshot.ready_sessions < self.config.startup_min_healthy_sessions.get() {
			return Err(ApiError::new(
				503,
				ApiErrorKind::PoolExhausted,
				format!(
					"{} Reddit API sessions ready; {} required",
					snapshot.ready_sessions, self.config.startup_min_healthy_sessions
				),
			));
		}

		let response = self
			.send(RedditRequest {
				method: Method::GET,
				base: RedditBase::OAuth,
				path: "/r/reddit/about.json?raw_json=1".into(),
				quarantine: true,
				follow_redirects: true,
				cost: RateCost::ONE,
				retry_policy: self.default_retry_policy(),
			})
			.await?;

		validate_rate_headers(&response.headers)?;

		if deep {
			for id in self.pool.ready_session_ids().await {
				let lease = self.pool.acquire_specific(id, RateCost::ONE).await?;
				let response = self
					.send_with_lease(
						&RedditRequest {
							method: Method::GET,
							base: RedditBase::OAuth,
							path: "/api/v1/me.json?raw_json=1".into(),
							quarantine: true,
							follow_redirects: true,
							cost: RateCost::ONE,
							retry_policy: RetryPolicy { max_attempts: NonZeroUsize::new(1).unwrap() },
						},
						&lease,
					)
					.await?;
				validate_rate_headers(&response.headers)?;
			}
		}

		Ok(())
	}

	pub async fn pool_snapshot(&self) -> crate::reddit::pool::PoolSnapshot {
		self.pool.snapshot().await
	}

	fn default_retry_policy(&self) -> RetryPolicy {
		RetryPolicy {
			max_attempts: self.config.max_attempts_per_api_request,
		}
	}

	async fn media_user_agent(&self) -> Option<HeaderValue> {
		self.pool
			.acquire(&HashSet::new(), RateCost::ZERO)
			.await
			.ok()
			.map(|lease| lease.token.user_agent.clone())
	}

	async fn get_json_cache(&self, key: &JsonCacheKey) -> Option<Value> {
		let mut cache = self.json_cache.lock().await;
		if let Some((expires_at, value)) = cache.get(key) {
			if *expires_at > Instant::now() {
				return Some(value.clone());
			}
		}
		cache.remove(key);
		None
	}

	async fn join_json_wait(&self, key: &JsonCacheKey) -> Option<oneshot::Receiver<Result<Value, ApiError>>> {
		let mut waiters = self.json_waiters.lock().await;
		if let Some(waiters) = waiters.get_mut(key) {
			let (tx, rx) = oneshot::channel();
			waiters.push(tx);
			Some(rx)
		} else {
			waiters.insert(key.clone(), Vec::new());
			None
		}
	}

	async fn finish_json_wait(&self, key: &JsonCacheKey, result: Result<Value, ApiError>) {
		if let Some(waiters) = self.json_waiters.lock().await.remove(key) {
			for waiter in waiters {
				let _ = waiter.send(result.clone());
			}
		}
	}

	async fn get_canonical_cache(&self, key: &CanonicalCacheKey) -> Option<Option<String>> {
		let mut cache = self.canonical_cache.lock().await;
		if let Some((expires_at, value)) = cache.get(key) {
			if *expires_at > Instant::now() {
				return Some(value.clone());
			}
		}
		cache.remove(key);
		None
	}

	async fn join_canonical_wait(&self, key: &CanonicalCacheKey) -> Option<oneshot::Receiver<Result<Option<String>, ApiError>>> {
		let mut waiters = self.canonical_waiters.lock().await;
		if let Some(waiters) = waiters.get_mut(key) {
			let (tx, rx) = oneshot::channel();
			waiters.push(tx);
			Some(rx)
		} else {
			waiters.insert(key.clone(), Vec::new());
			None
		}
	}

	async fn finish_canonical_wait(&self, key: &CanonicalCacheKey, result: Result<Option<String>, ApiError>) {
		if let Some(waiters) = self.canonical_waiters.lock().await.remove(key) {
			for waiter in waiters {
				let _ = waiter.send(result.clone());
			}
		}
	}
}

fn is_rate_limited(response: &RedditResponse) -> bool {
	response.status.as_u16() == 429 || (response.status.as_u16() == 403 && response.headers.get("retry-after").is_some())
}

fn validate_rate_headers(headers: &HeaderMap) -> Result<(), ApiError> {
	for name in ["x-ratelimit-remaining", "x-ratelimit-used", "x-ratelimit-reset"] {
		if let Some(value) = headers.get(name) {
			value
				.to_str()
				.ok()
				.and_then(|value| value.parse::<f32>().ok())
				.ok_or_else(|| ApiError::new(502, ApiErrorKind::InvalidResponse, format!("Reddit rate-limit header {name} was not parseable")))?;
		}
	}
	Ok(())
}

fn into_hyper_response(response: WreqResponse) -> HyperResponse<Body> {
	let status = response.status();
	let version = response.version();

	let mut builder = HyperResponse::builder().status(status.as_u16()).version(match version {
		wreq::Version::HTTP_09 => hyper::Version::HTTP_09,
		wreq::Version::HTTP_10 => hyper::Version::HTTP_10,
		wreq::Version::HTTP_11 => hyper::Version::HTTP_11,
		wreq::Version::HTTP_2 => hyper::Version::HTTP_2,
		wreq::Version::HTTP_3 => hyper::Version::HTTP_3,
		_ => hyper::Version::HTTP_11,
	});

	for (name, value) in response.headers() {
		builder = builder.header(
			header::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap(),
			header::HeaderValue::from_bytes(value.as_bytes()).unwrap(),
		);
	}

	builder.body(Body::wrap_stream(response.bytes_stream())).unwrap()
}
