use std::{fmt, num::NonZeroUsize, time::Duration};
use wreq::{header::HeaderMap, Method, StatusCode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiErrorKind {
	RedditStatus,
	RedditJson,
	RateLimited,
	PoolExhausted,
	Auth,
	Transport,
	InvalidRedirect,
	InvalidResponse,
	Config,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiError {
	pub status: u16,
	pub kind: ApiErrorKind,
	pub message: String,
	pub retry_after: Option<Duration>,
}

impl ApiError {
	pub fn new(status: u16, kind: ApiErrorKind, message: impl Into<String>) -> Self {
		Self {
			status,
			kind,
			message: message.into(),
			retry_after: None,
		}
	}

	pub fn with_retry_after(mut self, retry_after: Option<Duration>) -> Self {
		self.retry_after = retry_after;
		self
	}
}

impl fmt::Display for ApiError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.message)
	}
}

impl std::error::Error for ApiError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RedditBase {
	OAuth,
	Alternative,
	Short,
}

impl RedditBase {
	pub fn url(self) -> &'static str {
		match self {
			Self::OAuth => "https://oauth.reddit.com",
			Self::Alternative => "https://www.reddit.com",
			Self::Short => "https://redd.it",
		}
	}

	pub fn host(self) -> &'static str {
		match self {
			Self::OAuth => "oauth.reddit.com",
			Self::Alternative => "www.reddit.com",
			Self::Short => "redd.it",
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RateCost(pub u16);

impl RateCost {
	pub const ZERO: Self = Self(0);
	pub const ONE: Self = Self(1);
}

#[derive(Clone, Debug)]
pub struct RetryPolicy {
	pub max_attempts: NonZeroUsize,
}

#[derive(Clone, Debug)]
pub struct RedditRequest {
	pub method: Method,
	pub base: RedditBase,
	pub path: String,
	pub quarantine: bool,
	pub follow_redirects: bool,
	pub cost: RateCost,
	pub retry_policy: RetryPolicy,
}

#[derive(Clone, Debug)]
pub struct RedditResponse {
	pub status: StatusCode,
	pub headers: HeaderMap,
	pub body: Vec<u8>,
}
