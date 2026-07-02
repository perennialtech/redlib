use crate::{
	config::{QuotaExhaustionPolicy, RedditConfig, StartupPolicy},
	reddit::{
		request::{ApiError, ApiErrorKind, RateCost},
		session::{compare_scores, BackendKind, OAuthSession, SessionHealth, SessionHealthSummary, SessionId, SessionLease},
	},
};
use log::{error, info, warn};
use std::{
	collections::{BTreeMap, HashSet},
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc,
	},
	time::{Duration, Instant},
};
use tokio::{
	sync::{watch, RwLock, Semaphore},
	task::JoinSet,
	time::sleep,
};

pub struct OAuthSessionPool {
	sessions: RwLock<Vec<Arc<OAuthSession>>>,
	selection_cursor: AtomicUsize,
	next_session_id: AtomicUsize,
	config: RedditConfig,
	shutdown: watch::Sender<bool>,
}

#[derive(Clone, Debug)]
pub struct PoolSnapshot {
	pub configured_sessions: usize,
	pub ready_sessions: usize,
	pub refreshing_sessions: usize,
	pub cooling_down_sessions: usize,
	pub disabled_sessions: usize,
	pub aggregate_remaining: f32,
	pub soonest_reset_in: Option<Duration>,
	pub backend_counts: BTreeMap<BackendKind, usize>,
	pub sessions: Vec<SessionSnapshot>,
}

#[derive(Clone, Debug)]
pub struct SessionSnapshot {
	pub id: SessionId,
	pub backend: BackendKind,
	pub health: SessionHealthSummary,
	pub remaining: f32,
	pub reset_in: Option<Duration>,
	pub token_expires_in: Option<Duration>,
	pub in_flight: usize,
}

impl OAuthSessionPool {
	pub async fn bootstrap(config: RedditConfig) -> Result<Arc<Self>, ApiError> {
		let semaphore = Arc::new(Semaphore::new(config.bootstrap_concurrency.get()));
		let mut tasks = JoinSet::new();

		for id in 0..config.session_count.get() {
			let permit = semaphore.clone().acquire_owned().await.expect("bootstrap semaphore is open");
			let session_config = config.clone();
			tasks.spawn(async move {
				let _permit = permit;
				OAuthSession::bootstrap(id, session_config).await
			});
		}

		let mut sessions = Vec::new();
		let mut failures = Vec::new();

		while let Some(result) = tasks.join_next().await {
			match result {
				Ok(Ok(session)) => sessions.push(session),
				Ok(Err(err)) => failures.push(err),
				Err(err) => failures.push(ApiError::new(502, ApiErrorKind::Auth, format!("session bootstrap task failed: {err}"))),
			}
		}

		match config.startup_policy {
			StartupPolicy::RequireAll if sessions.len() != config.session_count.get() => {
				let message = failures
					.first()
					.map(|err| err.message.clone())
					.unwrap_or_else(|| "not all Reddit API sessions authenticated".into());
				return Err(ApiError::new(502, ApiErrorKind::Auth, message));
			}
			StartupPolicy::RequireMin if sessions.len() < config.startup_min_healthy_sessions.get() => {
				return Err(ApiError::new(
					502,
					ApiErrorKind::Auth,
					format!(
						"only {} Reddit API sessions authenticated; {} required",
						sessions.len(),
						config.startup_min_healthy_sessions
					),
				));
			}
			_ => {}
		}

		let (shutdown, _) = watch::channel(false);
		let next_session_id = sessions
			.iter()
			.map(|session| session.id)
			.max()
			.map(|max| max + 1)
			.unwrap_or(0);

		let pool = Arc::new(Self {
			sessions: RwLock::new(sessions),
			selection_cursor: AtomicUsize::new(0),
			next_session_id: AtomicUsize::new(next_session_id),
			config,
			shutdown,
		});

		pool.clone().start_supervisor();
		let snapshot = pool.snapshot().await;
		info!(
			"Created Reddit API session pool: configured={} ready={} backend_mix={:?}",
			snapshot.configured_sessions, snapshot.ready_sessions, snapshot.backend_counts
		);

		Ok(pool)
	}

	pub async fn acquire(&self, excluded: &HashSet<SessionId>, cost: RateCost) -> Result<SessionLease, ApiError> {
		let sessions = self.sessions.read().await.clone();
		if sessions.is_empty() {
			return Err(self.exhausted_error().await);
		}

		let start = self.selection_cursor.fetch_add(1, Ordering::SeqCst) % sessions.len();
		let mut best: Option<(Arc<OAuthSession>, f32)> = None;

		for offset in 0..sessions.len() {
			let session = sessions[(start + offset) % sessions.len()].clone();
			if excluded.contains(&session.id) {
				continue;
			}
			let Some(score) = session.score(self.config.reserve_remaining_per_session, 0.75, 3.0).await else {
				continue;
			};
			if best.as_ref().is_none_or(|(_, best_score)| compare_scores(score, *best_score).is_gt()) {
				best = Some((session, score));
			}
		}

		if let Some((session, _)) = best {
			Ok(SessionLease::new(session, cost))
		} else {
			Err(self.exhausted_error().await)
		}
	}

	pub async fn acquire_specific(&self, id: SessionId, cost: RateCost) -> Result<SessionLease, ApiError> {
		let session = self
			.sessions
			.read()
			.await
			.iter()
			.find(|session| session.id == id)
			.cloned()
			.ok_or_else(|| ApiError::new(503, ApiErrorKind::PoolExhausted, format!("Reddit API session {id} does not exist")))?;

		let health = session.health_summary();
		if health != SessionHealthSummary::Ready {
			return Err(ApiError::new(
				503,
				ApiErrorKind::PoolExhausted,
				format!("Reddit API session {id} is not ready: {health:?}"),
			));
		}

		Ok(SessionLease::new(session, cost))
	}

	pub async fn ready_session_ids(&self) -> Vec<SessionId> {
		self.sessions
			.read()
			.await
			.iter()
			.filter(|session| session.health_summary() == SessionHealthSummary::Ready)
			.map(|session| session.id)
			.collect()
	}

	pub async fn snapshot(&self) -> PoolSnapshot {
		let sessions = self.sessions.read().await.clone();
		let mut snapshot = PoolSnapshot {
			configured_sessions: self.config.session_count.get(),
			ready_sessions: 0,
			refreshing_sessions: 0,
			cooling_down_sessions: 0,
			disabled_sessions: 0,
			aggregate_remaining: 0.0,
			soonest_reset_in: None,
			backend_counts: BTreeMap::new(),
			sessions: Vec::with_capacity(sessions.len()),
		};

		for session in sessions {
			let health = session.health_summary();
			match health {
				SessionHealthSummary::Ready => snapshot.ready_sessions += 1,
				SessionHealthSummary::Refreshing => snapshot.refreshing_sessions += 1,
				SessionHealthSummary::Cooldown => snapshot.cooling_down_sessions += 1,
				SessionHealthSummary::Disabled => snapshot.disabled_sessions += 1,
				_ => {}
			}

			*snapshot.backend_counts.entry(session.backend_kind()).or_insert(0) += 1;

			let rate_limit = session.rate_limit.lock().await;
			snapshot.aggregate_remaining += rate_limit.remaining;
			let reset_in = rate_limit.soonest_reset().and_then(|instant| instant.checked_duration_since(Instant::now()));
			if let Some(reset_in) = reset_in {
				snapshot.soonest_reset_in = Some(snapshot.soonest_reset_in.map_or(reset_in, |old| old.min(reset_in)));
			}

			snapshot.sessions.push(SessionSnapshot {
				id: session.id,
				backend: session.backend_kind(),
				health,
				remaining: rate_limit.remaining,
				reset_in,
				token_expires_in: session.token_expires_in(),
				in_flight: session.in_flight.load(Ordering::SeqCst),
			});
		}

		snapshot
	}

	pub async fn shutdown(&self) {
		let _ = self.shutdown.send(true);
		for session in self.sessions.read().await.iter() {
			let _ = session.health.send(SessionHealth::ShuttingDown);
		}
	}

	fn start_supervisor(self: Arc<Self>) {
		tokio::spawn(async move {
			let mut shutdown = self.shutdown.subscribe();

			loop {
				tokio::select! {
					_ = shutdown.changed() => {
						if *shutdown.borrow() {
							break;
						}
					}
					_ = sleep(Duration::from_secs(1)) => {
						self.supervise_once().await;
					}
				}
			}

			let sessions = self.sessions.read().await.clone();
			for session in sessions {
				let _ = session.health.send(SessionHealth::ShuttingDown);
			}
		});
	}

	async fn supervise_once(&self) {
		let sessions = self.sessions.read().await.clone();

		for session in &sessions {
			session.maybe_leave_cooldown().await;
			self.maybe_refresh(session.clone()).await;
			session.apply_quota_policy().await;
		}

		self.replace_disabled_sessions().await;
		self.fill_to_target().await;
	}

	async fn maybe_refresh(&self, session: Arc<OAuthSession>) {
		let token = session.token.load_full();
		let jitter_seconds = if self.config.refresh_jitter.is_zero() {
			0
		} else {
			fastrand::u64(..=self.config.refresh_jitter.as_secs())
		};
		let refresh_margin = self.config.refresh_margin + Duration::from_secs(jitter_seconds);
		let refresh_at = token.expires_at.checked_sub(refresh_margin).unwrap_or_else(Instant::now);

		if refresh_at <= Instant::now() && matches!(session.health_summary(), SessionHealthSummary::Ready | SessionHealthSummary::Degraded) {
			tokio::spawn(async move {
				if let Err(err) = session.refresh_token().await {
					error!("failed to refresh Reddit API session {}: {}", session.id, err);
					let _ = session.health.send(SessionHealth::Degraded { reason: err.message });
				}
			});
		}
	}

	async fn replace_disabled_sessions(&self) {
		let mut sessions = self.sessions.write().await;
		for slot in sessions.iter_mut() {
			if slot.health_summary() == SessionHealthSummary::Disabled {
				let id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
				match OAuthSession::bootstrap(id, self.config.clone()).await {
					Ok(new_session) => *slot = new_session,
					Err(err) => warn!("failed to replace disabled Reddit API session: {err}"),
				}
			}
		}
	}

	async fn fill_to_target(&self) {
		loop {
			let current = self.sessions.read().await.len();
			if current >= self.config.session_count.get() {
				break;
			}

			let id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
			match OAuthSession::bootstrap(id, self.config.clone()).await {
				Ok(session) => self.sessions.write().await.push(session),
				Err(err) => {
					warn!("failed to fill Reddit API session pool: {err}");
					break;
				}
			}
		}
	}

	async fn exhausted_error(&self) -> ApiError {
		let snapshot = self.snapshot().await;
		let message = match snapshot.soonest_reset_in {
			Some(duration) => format!("All Reddit API sessions are rate limited. Try refreshing in {} seconds.", duration.as_secs().max(1)),
			None => "No Reddit API sessions are currently available.".to_string(),
		};

		ApiError::new(429, ApiErrorKind::PoolExhausted, message).with_retry_after(snapshot.soonest_reset_in)
	}

	pub fn quota_policy(&self) -> QuotaExhaustionPolicy {
		self.config.quota_exhaustion_policy
	}
}
