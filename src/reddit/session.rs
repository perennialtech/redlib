use crate::{
	config::{QuotaExhaustionPolicy, RedditConfig},
	reddit::{
		oauth::{AuthError, OAuthBackendImpl, SecretString},
		request::{ApiError, ApiErrorKind, RateCost},
		transport::build_reddit_transport,
	},
};
use arc_swap::ArcSwap;
use log::{error, info, warn};
use std::{
	cmp::Ordering as CmpOrdering,
	fmt,
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc,
	},
	time::{Duration, Instant},
};
use tokio::sync::{watch, Mutex};
use wreq::{
	header::{HeaderMap, HeaderValue, AUTHORIZATION, RETRY_AFTER, USER_AGENT},
	Client as WreqClient,
};

pub type SessionId = usize;
pub use crate::reddit::oauth::BackendKind;

#[derive(Clone)]
pub struct TokenState {
	pub access_token: SecretString,
	pub expires_at: Instant,
	pub auth_headers: HeaderMap,
	pub user_agent: HeaderValue,
}

impl fmt::Debug for TokenState {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("TokenState")
			.field("access_token", &"[redacted]")
			.field("expires_at", &self.expires_at)
			.field("auth_headers", &"[redacted]")
			.field("user_agent", &self.user_agent)
			.finish()
	}
}

#[derive(Clone, Debug)]
pub enum CooldownReason {
	RateLimited,
	RetryAfter,
	QuotaReserve,
	TransportFailures,
}

#[derive(Clone, Debug)]
pub enum SessionHealth {
	Starting,
	Ready,
	Refreshing,
	Cooldown { until: Instant, reason: CooldownReason },
	Degraded { reason: String },
	Disabled { reason: String },
	ShuttingDown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionHealthSummary {
	Starting,
	Ready,
	Refreshing,
	Cooldown,
	Degraded,
	Disabled,
	ShuttingDown,
}

impl From<&SessionHealth> for SessionHealthSummary {
	fn from(value: &SessionHealth) -> Self {
		match value {
			SessionHealth::Starting => Self::Starting,
			SessionHealth::Ready => Self::Ready,
			SessionHealth::Refreshing => Self::Refreshing,
			SessionHealth::Cooldown { .. } => Self::Cooldown,
			SessionHealth::Degraded { .. } => Self::Degraded,
			SessionHealth::Disabled { .. } => Self::Disabled,
			SessionHealth::ShuttingDown => Self::ShuttingDown,
		}
	}
}

#[derive(Clone, Debug)]
pub struct RateLimitState {
	pub remaining: f32,
	pub used: u32,
	pub limit_estimate: f32,
	pub reset_at: Option<Instant>,
	pub last_update: Instant,
	pub cooldown_until: Option<Instant>,
	pub consecutive_429s: u32,
	pub consecutive_transport_failures: u32,
	pub headers_seen: bool,
}

impl Default for RateLimitState {
	fn default() -> Self {
		Self {
			remaining: 99.0,
			used: 0,
			limit_estimate: 99.0,
			reset_at: None,
			last_update: Instant::now(),
			cooldown_until: None,
			consecutive_429s: 0,
			consecutive_transport_failures: 0,
			headers_seen: false,
		}
	}
}

impl RateLimitState {
	pub fn reserve(&mut self, cost: RateCost) {
		if cost.0 > 0 {
			self.remaining = (self.remaining - cost.0 as f32).max(0.0);
			self.last_update = Instant::now();
		}
	}

	pub fn update_from_headers(&mut self, headers: &HeaderMap) {
		let now = Instant::now();

		if let Some(remaining) = headers
			.get("x-ratelimit-remaining")
			.and_then(|val| val.to_str().ok())
			.and_then(|val| val.parse::<f32>().ok())
		{
			self.remaining = remaining;
			self.headers_seen = true;
		}
		if let Some(used) = headers.get("x-ratelimit-used").and_then(|val| val.to_str().ok()).and_then(|val| val.parse::<u32>().ok()) {
			self.used = used;
			self.headers_seen = true;
		}
		if let Some(reset) = headers.get("x-ratelimit-reset").and_then(|val| val.to_str().ok()).and_then(|val| val.parse::<f32>().ok()) {
			self.reset_at = Some(now + Duration::from_secs_f32(reset.max(0.0)));
			self.headers_seen = true;
		}
		if let Some(retry_after) = parse_retry_after(headers) {
			self.cooldown_until = Some(now + retry_after);
		}

		self.limit_estimate = self.limit_estimate.max(self.remaining + self.used as f32);
		self.last_update = now;
	}

	pub fn is_cooling_down(&self) -> bool {
		self.cooldown_until.is_some_and(|until| until > Instant::now())
	}

	pub fn soonest_reset(&self) -> Option<Instant> {
		match (self.reset_at, self.cooldown_until) {
			(Some(a), Some(b)) => Some(a.min(b)),
			(Some(a), None) => Some(a),
			(None, Some(b)) => Some(b),
			(None, None) => None,
		}
	}
}

pub struct OAuthSession {
	pub id: SessionId,
	pub backend: Mutex<OAuthBackendImpl>,
	pub transport: WreqClient,
	pub token: ArcSwap<TokenState>,
	pub rate_limit: Mutex<RateLimitState>,
	pub health: watch::Sender<SessionHealth>,
	pub in_flight: AtomicUsize,
	pub refresh_gate: Mutex<()>,
	config: RedditConfig,
}

impl OAuthSession {
	pub async fn bootstrap(id: SessionId, config: RedditConfig) -> Result<Arc<Self>, ApiError> {
		let transport = build_reddit_transport();
		let mut backend = OAuthBackendImpl::new_for_policy(config.backend_policy);

		let auth = match backend.authenticate(&transport).await {
			Ok(auth) => auth,
			Err(first_err) => {
				if let Some(mut fallback) = OAuthBackendImpl::fallback_for_policy(config.backend_policy) {
					warn!("session {id}: primary OAuth backend failed ({first_err}); trying fallback backend");
					match fallback.authenticate(&transport).await {
						Ok(auth) => {
							backend = fallback;
							auth
						}
						Err(second_err) => {
							return Err(auth_error(id, second_err));
						}
					}
				} else {
					return Err(auth_error(id, first_err));
				}
			}
		};

		let token = build_token_state(&backend, auth)?;
		let (health, _) = watch::channel(SessionHealth::Ready);

		info!("Created Reddit API session {id} with backend {:?}", backend.kind());

		Ok(Arc::new(Self {
			id,
			backend: Mutex::new(backend),
			transport,
			token: ArcSwap::from_pointee(token),
			rate_limit: Mutex::new(RateLimitState::default()),
			health,
			in_flight: AtomicUsize::new(0),
			refresh_gate: Mutex::new(()),
			config,
		}))
	}

	pub fn backend_kind(&self) -> BackendKind {
		self.backend.try_lock().map(|backend| backend.kind()).unwrap_or(BackendKind::GenericWeb)
	}

	pub fn health_summary(&self) -> SessionHealthSummary {
		SessionHealthSummary::from(&*self.health.borrow())
	}

	pub fn token_expires_in(&self) -> Option<Duration> {
		self.token.load().expires_at.checked_duration_since(Instant::now())
	}

	pub fn token_is_fresh(&self, danger_window: Duration) -> bool {
		self
			.token
			.load()
			.expires_at
			.checked_duration_since(Instant::now())
			.is_some_and(|duration| duration > danger_window)
	}

	pub async fn reserve_cost(&self, cost: RateCost) {
		self.rate_limit.lock().await.reserve(cost);
	}

	pub async fn update_rate_limit(&self, headers: &HeaderMap, status: wreq::StatusCode) {
		let mut state = self.rate_limit.lock().await;
		state.update_from_headers(headers);
		if status.as_u16() == 429 {
			state.consecutive_429s += 1;
			let until = state.soonest_reset().unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
			state.cooldown_until = Some(until);
			let _ = self.health.send(SessionHealth::Cooldown {
				until,
				reason: CooldownReason::RateLimited,
			});
		} else {
			state.consecutive_429s = 0;
			state.consecutive_transport_failures = 0;
		}
		if status.as_u16() == 403 && headers.get(RETRY_AFTER).is_some() {
			let until = Instant::now() + parse_retry_after(headers).unwrap_or(Duration::from_secs(30));
			state.cooldown_until = Some(until);
			let _ = self.health.send(SessionHealth::Cooldown {
				until,
				reason: CooldownReason::RetryAfter,
			});
		}
	}

	pub async fn mark_transport_failure(&self) {
		let mut state = self.rate_limit.lock().await;
		state.consecutive_transport_failures += 1;
		if state.consecutive_transport_failures >= 3 {
			let until = Instant::now() + Duration::from_secs(15);
			state.cooldown_until = Some(until);
			let _ = self.health.send(SessionHealth::Cooldown {
				until,
				reason: CooldownReason::TransportFailures,
			});
		}
	}

	pub async fn maybe_leave_cooldown(&self) {
		let mut state = self.rate_limit.lock().await;
		if state.cooldown_until.is_some_and(|until| until <= Instant::now()) {
			state.cooldown_until = None;
			let _ = self.health.send(SessionHealth::Ready);
		}
	}

	pub async fn refresh_token(&self) -> Result<(), ApiError> {
		let _guard = self.refresh_gate.lock().await;
		let _ = self.health.send(SessionHealth::Refreshing);

		let mut backend = self.backend.lock().await;
		let auth = backend.authenticate(&self.transport).await.map_err(|err| auth_error(self.id, err))?;
		let token = build_token_state(&backend, auth)?;

		self.token.store(Arc::new(token));
		let _ = self.health.send(SessionHealth::Ready);
		info!("Refreshed Reddit API session {}", self.id);
		Ok(())
	}

	pub async fn rotate_identity(&self) -> Result<(), ApiError> {
		let _guard = self.refresh_gate.lock().await;
		let _ = self.health.send(SessionHealth::Starting);

		let mut new_backend = OAuthBackendImpl::new_for_policy(self.config.backend_policy);
		let auth = new_backend.authenticate(&self.transport).await.map_err(|err| auth_error(self.id, err))?;
		let token = build_token_state(&new_backend, auth)?;

		*self.backend.lock().await = new_backend;
		self.token.store(Arc::new(token));
		*self.rate_limit.lock().await = RateLimitState::default();
		let _ = self.health.send(SessionHealth::Ready);
		info!("Rotated Reddit API session {}", self.id);
		Ok(())
	}

	pub async fn score(&self, reserve_remaining: u16, pressure_penalty: f32, failure_penalty: f32) -> Option<f32> {
		self.maybe_leave_cooldown().await;

		let health = self.health.borrow().clone();
		if !matches!(health, SessionHealth::Ready) {
			return None;
		}
		if !self.token_is_fresh(Duration::from_secs(10)) {
			return None;
		}

		let state = self.rate_limit.lock().await;
		if state.is_cooling_down() || state.remaining <= reserve_remaining as f32 {
			return None;
		}

		let available = (state.remaining - reserve_remaining as f32).max(0.0);
		let pressure = self.in_flight.load(Ordering::SeqCst) as f32 * pressure_penalty;
		let failures = (state.consecutive_429s + state.consecutive_transport_failures) as f32 * failure_penalty;

		Some(available - pressure - failures)
	}

	pub async fn apply_quota_policy(&self) {
		let mut state = self.rate_limit.lock().await;
		if state.remaining <= self.config.reserve_remaining_per_session as f32 {
			let until = state.reset_at.unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
			state.cooldown_until = Some(until);
			let _ = self.health.send(SessionHealth::Cooldown {
				until,
				reason: CooldownReason::QuotaReserve,
			});
			drop(state);

			if self.config.quota_exhaustion_policy == QuotaExhaustionPolicy::Rotate {
				if let Err(err) = self.rotate_identity().await {
					error!("failed to rotate exhausted Reddit API session {}: {}", self.id, err);
				}
			}
		}
	}
}

pub struct SessionLease {
	pub session: Arc<OAuthSession>,
	pub token: Arc<TokenState>,
	pub cost: RateCost,
}

impl SessionLease {
	pub fn new(session: Arc<OAuthSession>, cost: RateCost) -> Self {
		session.in_flight.fetch_add(1, Ordering::SeqCst);
		let token = session.token.load_full();
		Self { session, token, cost }
	}
}

impl Drop for SessionLease {
	fn drop(&mut self) {
		self.session.in_flight.fetch_sub(1, Ordering::SeqCst);
	}
}

pub fn compare_scores(a: f32, b: f32) -> CmpOrdering {
	a.partial_cmp(&b).unwrap_or(CmpOrdering::Equal)
}

fn build_token_state(backend: &OAuthBackendImpl, auth: crate::reddit::oauth::AuthResponse) -> Result<TokenState, ApiError> {
	let mut auth_headers = backend.base_headers();
	for (name, value) in auth.additional_headers.iter() {
		auth_headers.insert(name.clone(), value.clone());
	}

	let authorization = HeaderValue::from_str(&format!("Bearer {}", auth.token.expose_secret()))
		.map_err(|_| ApiError::new(500, ApiErrorKind::Auth, "OAuth token could not be converted to an Authorization header"))?;
	auth_headers.insert(AUTHORIZATION, authorization);

	let user_agent = auth_headers.get(USER_AGENT).cloned().unwrap_or_else(|| backend.user_agent());

	Ok(TokenState {
		access_token: auth.token,
		expires_at: Instant::now() + auth.expires_in,
		auth_headers,
		user_agent,
	})
}

fn auth_error(id: SessionId, err: AuthError) -> ApiError {
	ApiError::new(502, ApiErrorKind::Auth, format!("Reddit API session {id} authentication failed: {err}"))
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
	headers
		.get(RETRY_AFTER)
		.and_then(|val| val.to_str().ok())
		.and_then(|val| val.parse::<f32>().ok())
		.map(|seconds| Duration::from_secs_f32(seconds.max(0.0)))
}
