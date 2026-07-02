use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use std::{
	env::var,
	fmt::{self, Display},
	fs::read_to_string,
	num::NonZeroUsize,
	str::FromStr,
	sync::LazyLock,
	time::Duration,
};

/// This is the local static that is initialized at runtime and contains the
/// typed instance settings.
pub static CONFIG: LazyLock<Config> = LazyLock::new(Config::load);

/// This serves as the frontend for an archival API - on removed comments, this URL
/// will be the base of a link, to display removed content (on another site).
pub const DEFAULT_PUSHSHIFT_FRONTEND: &str = "undelete.pullpush.io";

#[derive(Clone, Debug, Serialize)]
pub struct Config {
	pub instance: InstanceConfig,
	pub defaults: DefaultUserConfig,
	pub reddit: RedditConfig,
}

#[derive(Clone, Debug, Serialize)]
pub struct InstanceConfig {
	pub sfw_only: bool,
	pub banner: String,
	pub robots_disable_indexing: bool,
	pub pushshift_frontend: String,
	pub enable_rss: bool,
	pub full_url: Option<String>,
	pub external_media_domain: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DefaultUserConfig {
	pub theme: String,
	pub front_page: String,
	pub layout: String,
	pub wide: bool,
	pub comment_sort: String,
	pub post_sort: String,
	pub blur_spoiler: bool,
	pub show_nsfw: bool,
	pub blur_nsfw: bool,
	pub use_hls: bool,
	pub hide_hls_notification: bool,
	pub hide_awards: bool,
	pub hide_sidebar_and_summary: bool,
	pub hide_score: bool,
	pub subscriptions: String,
	pub filters: String,
	pub disable_visit_reddit_confirmation: bool,
	pub remove_default_feeds: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum StartupPolicy {
	RequireAll,
	RequireMin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum BackendPolicy {
	Auto,
	MobileSpoof,
	GenericWeb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum SelectionPolicy {
	RateLimitAware,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum QuotaExhaustionPolicy {
	Cooldown,
	Rotate,
}

#[derive(Clone, Debug, Serialize)]
pub struct RedditConfig {
	pub session_count: NonZeroUsize,
	pub startup_policy: StartupPolicy,
	pub startup_min_healthy_sessions: NonZeroUsize,
	pub backend_policy: BackendPolicy,
	pub selection_policy: SelectionPolicy,
	pub bootstrap_concurrency: NonZeroUsize,
	pub reserve_remaining_per_session: u16,
	pub refresh_margin: Duration,
	pub refresh_jitter: Duration,
	pub request_timeout: Duration,
	pub max_attempts_per_api_request: NonZeroUsize,
	pub quota_exhaustion_policy: QuotaExhaustionPolicy,
}

impl Default for Config {
	fn default() -> Self {
		Self {
			instance: InstanceConfig::default(),
			defaults: DefaultUserConfig::default(),
			reddit: RedditConfig::default(),
		}
	}
}

impl Default for InstanceConfig {
	fn default() -> Self {
		Self {
			sfw_only: false,
			banner: String::new(),
			robots_disable_indexing: false,
			pushshift_frontend: DEFAULT_PUSHSHIFT_FRONTEND.to_string(),
			enable_rss: false,
			full_url: None,
			external_media_domain: None,
		}
	}
}

impl Default for DefaultUserConfig {
	fn default() -> Self {
		Self {
			theme: "system".into(),
			front_page: "default".into(),
			layout: "card".into(),
			wide: false,
			comment_sort: "confidence".into(),
			post_sort: "hot".into(),
			blur_spoiler: false,
			show_nsfw: false,
			blur_nsfw: false,
			use_hls: false,
			hide_hls_notification: false,
			hide_awards: false,
			hide_sidebar_and_summary: false,
			hide_score: false,
			subscriptions: String::new(),
			filters: String::new(),
			disable_visit_reddit_confirmation: false,
			remove_default_feeds: false,
		}
	}
}

impl Default for RedditConfig {
	fn default() -> Self {
		Self {
			session_count: nz(10),
			startup_policy: StartupPolicy::RequireAll,
			startup_min_healthy_sessions: nz(1),
			backend_policy: BackendPolicy::Auto,
			selection_policy: SelectionPolicy::RateLimitAware,
			bootstrap_concurrency: nz(1),
			reserve_remaining_per_session: 2,
			refresh_margin: Duration::from_secs(120),
			refresh_jitter: Duration::from_secs(30),
			request_timeout: Duration::from_secs(5),
			max_attempts_per_api_request: nz(3),
			quota_exhaustion_policy: QuotaExhaustionPolicy::Cooldown,
		}
	}
}

fn nz(value: usize) -> NonZeroUsize {
	NonZeroUsize::new(value).expect("hard-coded non-zero configuration default")
}

impl<'de> Deserialize<'de> for Config {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = toml::Value::deserialize(deserializer).map_err(D::Error::custom)?;
		Self::from_toml_value(value).map_err(D::Error::custom)
	}
}

impl Config {
	/// Load typed configuration from `redlib.toml`/`libreddit.toml` and
	/// environment variables. Environment variables override TOML.
	pub fn load() -> Self {
		Self::try_load().unwrap_or_else(|err| panic!("invalid Redlib configuration: {err}"))
	}

	pub fn try_load() -> Result<Self, ConfigError> {
		let config = read_to_string("redlib.toml")
			.ok()
			.or_else(|| read_to_string("libreddit.toml").ok())
			.map(|file| toml::from_str::<Self>(&file))
			.transpose()
			.map_err(|err| ConfigError(err.to_string()))?
			.unwrap_or_default();

		let mut config = config;
		config.apply_env_overrides()?;
		config.validate()?;
		Ok(config)
	}

	fn from_toml_value(value: toml::Value) -> Result<Self, ConfigError> {
		let mut config = Self::default();

		set_string_from_toml(&value, &mut config.defaults.theme, &["REDLIB_DEFAULT_THEME", "LIBREDDIT_DEFAULT_THEME"]);
		set_string_from_toml(&value, &mut config.defaults.front_page, &["REDLIB_DEFAULT_FRONT_PAGE", "LIBREDDIT_DEFAULT_FRONT_PAGE"]);
		set_string_from_toml(&value, &mut config.defaults.layout, &["REDLIB_DEFAULT_LAYOUT", "LIBREDDIT_DEFAULT_LAYOUT"]);
		set_bool_from_toml(&value, &mut config.defaults.wide, &["REDLIB_DEFAULT_WIDE", "LIBREDDIT_DEFAULT_WIDE"])?;
		set_string_from_toml(
			&value,
			&mut config.defaults.comment_sort,
			&["REDLIB_DEFAULT_COMMENT_SORT", "LIBREDDIT_DEFAULT_COMMENT_SORT"],
		);
		set_string_from_toml(&value, &mut config.defaults.post_sort, &["REDLIB_DEFAULT_POST_SORT", "LIBREDDIT_DEFAULT_POST_SORT"]);
		set_bool_from_toml(
			&value,
			&mut config.defaults.blur_spoiler,
			&["REDLIB_DEFAULT_BLUR_SPOILER", "LIBREDDIT_DEFAULT_BLUR_SPOILER"],
		)?;
		set_bool_from_toml(&value, &mut config.defaults.show_nsfw, &["REDLIB_DEFAULT_SHOW_NSFW", "LIBREDDIT_DEFAULT_SHOW_NSFW"])?;
		set_bool_from_toml(&value, &mut config.defaults.blur_nsfw, &["REDLIB_DEFAULT_BLUR_NSFW", "LIBREDDIT_DEFAULT_BLUR_NSFW"])?;
		set_bool_from_toml(&value, &mut config.defaults.use_hls, &["REDLIB_DEFAULT_USE_HLS", "LIBREDDIT_DEFAULT_USE_HLS"])?;
		set_bool_from_toml(
			&value,
			&mut config.defaults.hide_hls_notification,
			&["REDLIB_DEFAULT_HIDE_HLS_NOTIFICATION", "LIBREDDIT_DEFAULT_HIDE_HLS_NOTIFICATION"],
		)?;
		set_bool_from_toml(&value, &mut config.defaults.hide_awards, &["REDLIB_DEFAULT_HIDE_AWARDS", "LIBREDDIT_DEFAULT_HIDE_AWARDS"])?;
		set_bool_from_toml(
			&value,
			&mut config.defaults.hide_sidebar_and_summary,
			&["REDLIB_DEFAULT_HIDE_SIDEBAR_AND_SUMMARY", "LIBREDDIT_DEFAULT_HIDE_SIDEBAR_AND_SUMMARY"],
		)?;
		set_bool_from_toml(&value, &mut config.defaults.hide_score, &["REDLIB_DEFAULT_HIDE_SCORE", "LIBREDDIT_DEFAULT_HIDE_SCORE"])?;
		set_string_from_toml(
			&value,
			&mut config.defaults.subscriptions,
			&["REDLIB_DEFAULT_SUBSCRIPTIONS", "LIBREDDIT_DEFAULT_SUBSCRIPTIONS"],
		);
		set_string_from_toml(&value, &mut config.defaults.filters, &["REDLIB_DEFAULT_FILTERS", "LIBREDDIT_DEFAULT_FILTERS"]);
		set_bool_from_toml(
			&value,
			&mut config.defaults.disable_visit_reddit_confirmation,
			&["REDLIB_DEFAULT_DISABLE_VISIT_REDDIT_CONFIRMATION", "LIBREDDIT_DEFAULT_DISABLE_VISIT_REDDIT_CONFIRMATION"],
		)?;
		set_bool_from_toml(&value, &mut config.defaults.remove_default_feeds, &["REDLIB_DEFAULT_REMOVE_DEFAULT_FEEDS"])?;

		set_bool_from_toml(&value, &mut config.instance.sfw_only, &["REDLIB_SFW_ONLY", "LIBREDDIT_SFW_ONLY"])?;
		set_string_from_toml(&value, &mut config.instance.banner, &["REDLIB_BANNER", "LIBREDDIT_BANNER"]);
		set_bool_from_toml(
			&value,
			&mut config.instance.robots_disable_indexing,
			&["REDLIB_ROBOTS_DISABLE_INDEXING", "LIBREDDIT_ROBOTS_DISABLE_INDEXING"],
		)?;
		set_string_from_toml(
			&value,
			&mut config.instance.pushshift_frontend,
			&["REDLIB_PUSHSHIFT_FRONTEND", "LIBREDDIT_PUSHSHIFT_FRONTEND"],
		);
		set_bool_from_toml(&value, &mut config.instance.enable_rss, &["REDLIB_ENABLE_RSS"])?;
		set_optional_string_from_toml(&value, &mut config.instance.full_url, &["REDLIB_FULL_URL"]);
		set_optional_string_from_toml(&value, &mut config.instance.external_media_domain, &["REDLIB_EXTERNAL_MEDIA_DOMAIN"]);

		if let Some(reddit) = value.get("reddit").and_then(toml::Value::as_table) {
			if let Some(v) = reddit.get("session_count") {
				config.reddit.session_count = parse_nonzero_value(v, "reddit.session_count")?;
			}
			if let Some(v) = reddit.get("startup_policy").and_then(toml::Value::as_str) {
				config.reddit.startup_policy = v.parse()?;
			}
			if let Some(v) = reddit.get("startup_min_healthy_sessions") {
				config.reddit.startup_min_healthy_sessions = parse_nonzero_value(v, "reddit.startup_min_healthy_sessions")?;
			}
			if let Some(v) = reddit.get("backend_policy").and_then(toml::Value::as_str) {
				config.reddit.backend_policy = v.parse()?;
			}
			if let Some(v) = reddit.get("selection_policy").and_then(toml::Value::as_str) {
				config.reddit.selection_policy = v.parse()?;
			}
			if let Some(v) = reddit.get("bootstrap_concurrency") {
				config.reddit.bootstrap_concurrency = parse_nonzero_value(v, "reddit.bootstrap_concurrency")?;
			}
			if let Some(v) = reddit.get("reserve_remaining_per_session") {
				config.reddit.reserve_remaining_per_session = parse_u16_value(v, "reddit.reserve_remaining_per_session")?;
			}
			if let Some(v) = reddit.get("refresh_margin_seconds") {
				config.reddit.refresh_margin = parse_positive_duration_value(v, "reddit.refresh_margin_seconds")?;
			}
			if let Some(v) = reddit.get("refresh_jitter_seconds") {
				config.reddit.refresh_jitter = parse_duration_value(v, "reddit.refresh_jitter_seconds")?;
			}
			if let Some(v) = reddit.get("request_timeout_seconds") {
				config.reddit.request_timeout = parse_positive_duration_value(v, "reddit.request_timeout_seconds")?;
			}
			if let Some(v) = reddit.get("max_attempts_per_api_request") {
				config.reddit.max_attempts_per_api_request = parse_nonzero_value(v, "reddit.max_attempts_per_api_request")?;
			}
			if let Some(v) = reddit.get("quota_exhaustion_policy").and_then(toml::Value::as_str) {
				config.reddit.quota_exhaustion_policy = v.parse()?;
			}
		}

		config.validate()?;
		Ok(config)
	}

	fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
		env_string(&mut self.defaults.theme, "REDLIB_DEFAULT_THEME");
		env_string(&mut self.defaults.front_page, "REDLIB_DEFAULT_FRONT_PAGE");
		env_string(&mut self.defaults.layout, "REDLIB_DEFAULT_LAYOUT");
		env_bool(&mut self.defaults.wide, "REDLIB_DEFAULT_WIDE")?;
		env_string(&mut self.defaults.comment_sort, "REDLIB_DEFAULT_COMMENT_SORT");
		env_string(&mut self.defaults.post_sort, "REDLIB_DEFAULT_POST_SORT");
		env_bool(&mut self.defaults.blur_spoiler, "REDLIB_DEFAULT_BLUR_SPOILER")?;
		env_bool(&mut self.defaults.show_nsfw, "REDLIB_DEFAULT_SHOW_NSFW")?;
		env_bool(&mut self.defaults.blur_nsfw, "REDLIB_DEFAULT_BLUR_NSFW")?;
		env_bool(&mut self.defaults.use_hls, "REDLIB_DEFAULT_USE_HLS")?;
		env_bool(&mut self.defaults.hide_hls_notification, "REDLIB_DEFAULT_HIDE_HLS_NOTIFICATION")?;
		env_bool(&mut self.defaults.hide_awards, "REDLIB_DEFAULT_HIDE_AWARDS")?;
		env_bool(&mut self.defaults.hide_sidebar_and_summary, "REDLIB_DEFAULT_HIDE_SIDEBAR_AND_SUMMARY")?;
		env_bool(&mut self.defaults.hide_score, "REDLIB_DEFAULT_HIDE_SCORE")?;
		env_string(&mut self.defaults.subscriptions, "REDLIB_DEFAULT_SUBSCRIPTIONS");
		env_string(&mut self.defaults.filters, "REDLIB_DEFAULT_FILTERS");
		env_bool(&mut self.defaults.disable_visit_reddit_confirmation, "REDLIB_DEFAULT_DISABLE_VISIT_REDDIT_CONFIRMATION")?;
		env_bool(&mut self.defaults.remove_default_feeds, "REDLIB_DEFAULT_REMOVE_DEFAULT_FEEDS")?;

		env_bool(&mut self.instance.sfw_only, "REDLIB_SFW_ONLY")?;
		env_string(&mut self.instance.banner, "REDLIB_BANNER");
		env_bool(&mut self.instance.robots_disable_indexing, "REDLIB_ROBOTS_DISABLE_INDEXING")?;
		env_string(&mut self.instance.pushshift_frontend, "REDLIB_PUSHSHIFT_FRONTEND");
		env_bool(&mut self.instance.enable_rss, "REDLIB_ENABLE_RSS")?;
		env_optional_string(&mut self.instance.full_url, "REDLIB_FULL_URL");
		env_optional_string(&mut self.instance.external_media_domain, "REDLIB_EXTERNAL_MEDIA_DOMAIN");

		env_nonzero(&mut self.reddit.session_count, "REDLIB_REDDIT_SESSION_COUNT")?;
		env_parse(&mut self.reddit.startup_policy, "REDLIB_REDDIT_STARTUP_POLICY")?;
		env_nonzero(&mut self.reddit.startup_min_healthy_sessions, "REDLIB_REDDIT_STARTUP_MIN_HEALTHY_SESSIONS")?;
		env_parse(&mut self.reddit.backend_policy, "REDLIB_REDDIT_BACKEND_POLICY")?;
		env_parse(&mut self.reddit.selection_policy, "REDLIB_REDDIT_SELECTION_POLICY")?;
		env_nonzero(&mut self.reddit.bootstrap_concurrency, "REDLIB_REDDIT_BOOTSTRAP_CONCURRENCY")?;
		env_u16(&mut self.reddit.reserve_remaining_per_session, "REDLIB_REDDIT_RESERVE_REMAINING_PER_SESSION")?;
		env_positive_duration(&mut self.reddit.refresh_margin, "REDLIB_REDDIT_REFRESH_MARGIN_SECONDS")?;
		env_duration(&mut self.reddit.refresh_jitter, "REDLIB_REDDIT_REFRESH_JITTER_SECONDS")?;
		env_positive_duration(&mut self.reddit.request_timeout, "REDLIB_REDDIT_REQUEST_TIMEOUT_SECONDS")?;
		env_nonzero(&mut self.reddit.max_attempts_per_api_request, "REDLIB_REDDIT_MAX_ATTEMPTS_PER_API_REQUEST")?;
		env_parse(&mut self.reddit.quota_exhaustion_policy, "REDLIB_REDDIT_QUOTA_EXHAUSTION_POLICY")?;

		Ok(())
	}

	pub fn validate(&self) -> Result<(), ConfigError> {
		if self.reddit.startup_min_healthy_sessions.get() > self.reddit.session_count.get() {
			return Err(ConfigError(format!(
				"reddit.startup_min_healthy_sessions ({}) must not exceed reddit.session_count ({})",
				self.reddit.startup_min_healthy_sessions, self.reddit.session_count
			)));
		}
		if self.reddit.refresh_margin.is_zero() {
			return Err(ConfigError("reddit.refresh_margin_seconds must be positive".into()));
		}
		if self.reddit.request_timeout.is_zero() {
			return Err(ConfigError("reddit.request_timeout_seconds must be positive".into()));
		}
		Ok(())
	}
}

#[derive(Clone, Debug)]
pub struct ConfigError(pub String);

impl Display for ConfigError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl std::error::Error for ConfigError {}

macro_rules! enum_parse {
	($ty:ty, {$($name:literal => $variant:path),+ $(,)?}) => {
		impl FromStr for $ty {
			type Err = ConfigError;

			fn from_str(input: &str) -> Result<Self, Self::Err> {
				match input.trim().to_ascii_lowercase().as_str() {
					$($name => Ok($variant),)+
					other => Err(ConfigError(format!("invalid {} value: {other}", stringify!($ty)))),
				}
			}
		}

		impl Display for $ty {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				let value = match self {
					$($variant => $name,)+
				};
				f.write_str(value)
			}
		}
	};
}

enum_parse!(StartupPolicy, {
	"require_all" => StartupPolicy::RequireAll,
	"require_min" => StartupPolicy::RequireMin,
});

enum_parse!(BackendPolicy, {
	"auto" => BackendPolicy::Auto,
	"mobile_spoof" => BackendPolicy::MobileSpoof,
	"generic_web" => BackendPolicy::GenericWeb,
});

enum_parse!(SelectionPolicy, {
	"rate_limit_aware" => SelectionPolicy::RateLimitAware,
});

enum_parse!(QuotaExhaustionPolicy, {
	"cooldown" => QuotaExhaustionPolicy::Cooldown,
	"rotate" => QuotaExhaustionPolicy::Rotate,
});

fn legacy_key(key: &str) -> String {
	key.replace("REDLIB_", "LIBREDDIT_")
}

fn env_value(key: &str) -> Option<String> {
	var(key).ok().or_else(|| var(legacy_key(key)).ok())
}

fn env_string(target: &mut String, key: &str) {
	if let Some(value) = env_value(key) {
		*target = value;
	}
}

fn env_optional_string(target: &mut Option<String>, key: &str) {
	if let Some(value) = env_value(key) {
		*target = if value.is_empty() { None } else { Some(value) };
	}
}

fn env_bool(target: &mut bool, key: &str) -> Result<(), ConfigError> {
	if let Some(value) = env_value(key) {
		*target = parse_bool(&value, key)?;
	}
	Ok(())
}

fn env_nonzero(target: &mut NonZeroUsize, key: &str) -> Result<(), ConfigError> {
	if let Some(value) = env_value(key) {
		*target = parse_nonzero_str(&value, key)?;
	}
	Ok(())
}

fn env_u16(target: &mut u16, key: &str) -> Result<(), ConfigError> {
	if let Some(value) = env_value(key) {
		*target = value.parse().map_err(|_| ConfigError(format!("{key} must be a u16")))?;
	}
	Ok(())
}

fn env_duration(target: &mut Duration, key: &str) -> Result<(), ConfigError> {
	if let Some(value) = env_value(key) {
		let seconds: u64 = value.parse().map_err(|_| ConfigError(format!("{key} must be seconds")))?;
		*target = Duration::from_secs(seconds);
	}
	Ok(())
}

fn env_positive_duration(target: &mut Duration, key: &str) -> Result<(), ConfigError> {
	if let Some(value) = env_value(key) {
		let seconds: u64 = value.parse().map_err(|_| ConfigError(format!("{key} must be positive seconds")))?;
		if seconds == 0 {
			return Err(ConfigError(format!("{key} must be positive")));
		}
		*target = Duration::from_secs(seconds);
	}
	Ok(())
}

fn env_parse<T>(target: &mut T, key: &str) -> Result<(), ConfigError>
where
	T: FromStr<Err = ConfigError>,
{
	if let Some(value) = env_value(key) {
		*target = value.parse()?;
	}
	Ok(())
}

fn set_string_from_toml(value: &toml::Value, target: &mut String, keys: &[&str]) {
	if let Some(found) = keys.iter().find_map(|key| value.get(*key).and_then(toml::Value::as_str)) {
		*target = found.to_string();
	}
}

fn set_optional_string_from_toml(value: &toml::Value, target: &mut Option<String>, keys: &[&str]) {
	if let Some(found) = keys.iter().find_map(|key| value.get(*key).and_then(toml::Value::as_str)) {
		*target = if found.is_empty() { None } else { Some(found.to_string()) };
	}
}

fn set_bool_from_toml(value: &toml::Value, target: &mut bool, keys: &[&str]) -> Result<(), ConfigError> {
	if let Some((key, found)) = keys.iter().find_map(|key| value.get(*key).map(|v| (*key, v))) {
		*target = match found {
			toml::Value::Boolean(value) => *value,
			toml::Value::String(value) => parse_bool(value, key)?,
			_ => return Err(ConfigError(format!("{key} must be a boolean or on/off string"))),
		};
	}
	Ok(())
}

fn parse_bool(value: &str, name: &str) -> Result<bool, ConfigError> {
	match value.trim().to_ascii_lowercase().as_str() {
		"on" | "true" | "1" | "yes" => Ok(true),
		"off" | "false" | "0" | "no" | "" => Ok(false),
		_ => Err(ConfigError(format!("{name} must be on/off"))),
	}
}

fn parse_nonzero_str(value: &str, name: &str) -> Result<NonZeroUsize, ConfigError> {
	let parsed: usize = value.parse().map_err(|_| ConfigError(format!("{name} must be a positive integer")))?;
	NonZeroUsize::new(parsed).ok_or_else(|| ConfigError(format!("{name} must be non-zero")))
}

fn parse_nonzero_value(value: &toml::Value, name: &str) -> Result<NonZeroUsize, ConfigError> {
	let parsed = value.as_integer().ok_or_else(|| ConfigError(format!("{name} must be an integer")))?;
	if parsed <= 0 {
		return Err(ConfigError(format!("{name} must be non-zero")));
	}
	NonZeroUsize::new(parsed as usize).ok_or_else(|| ConfigError(format!("{name} must be non-zero")))
}

fn parse_u16_value(value: &toml::Value, name: &str) -> Result<u16, ConfigError> {
	let parsed = value.as_integer().ok_or_else(|| ConfigError(format!("{name} must be an integer")))?;
	u16::try_from(parsed).map_err(|_| ConfigError(format!("{name} must fit in u16")))
}

fn parse_duration_value(value: &toml::Value, name: &str) -> Result<Duration, ConfigError> {
	let parsed = value.as_integer().ok_or_else(|| ConfigError(format!("{name} must be seconds")))?;
	if parsed < 0 {
		return Err(ConfigError(format!("{name} must be non-negative")));
	}
	Ok(Duration::from_secs(parsed as u64))
}

fn parse_positive_duration_value(value: &toml::Value, name: &str) -> Result<Duration, ConfigError> {
	let duration = parse_duration_value(value, name)?;
	if duration.is_zero() {
		return Err(ConfigError(format!("{name} must be positive")));
	}
	Ok(duration)
}

fn bool_setting(value: bool) -> String {
	if value { "on" } else { "off" }.to_string()
}

fn get_setting_from_config(name: &str, config: &Config) -> Option<String> {
	match name {
		"REDLIB_SFW_ONLY" => Some(bool_setting(config.instance.sfw_only)),
		"REDLIB_DEFAULT_THEME" => Some(config.defaults.theme.clone()),
		"REDLIB_DEFAULT_FRONT_PAGE" => Some(config.defaults.front_page.clone()),
		"REDLIB_DEFAULT_LAYOUT" => Some(config.defaults.layout.clone()),
		"REDLIB_DEFAULT_COMMENT_SORT" => Some(config.defaults.comment_sort.clone()),
		"REDLIB_DEFAULT_POST_SORT" => Some(config.defaults.post_sort.clone()),
		"REDLIB_DEFAULT_BLUR_SPOILER" => Some(bool_setting(config.defaults.blur_spoiler)),
		"REDLIB_DEFAULT_SHOW_NSFW" => Some(bool_setting(config.defaults.show_nsfw)),
		"REDLIB_DEFAULT_BLUR_NSFW" => Some(bool_setting(config.defaults.blur_nsfw)),
		"REDLIB_DEFAULT_USE_HLS" => Some(bool_setting(config.defaults.use_hls)),
		"REDLIB_DEFAULT_HIDE_HLS_NOTIFICATION" => Some(bool_setting(config.defaults.hide_hls_notification)),
		"REDLIB_DEFAULT_WIDE" => Some(bool_setting(config.defaults.wide)),
		"REDLIB_DEFAULT_HIDE_AWARDS" => Some(bool_setting(config.defaults.hide_awards)),
		"REDLIB_DEFAULT_HIDE_SIDEBAR_AND_SUMMARY" => Some(bool_setting(config.defaults.hide_sidebar_and_summary)),
		"REDLIB_DEFAULT_HIDE_SCORE" => Some(bool_setting(config.defaults.hide_score)),
		"REDLIB_DEFAULT_SUBSCRIPTIONS" => Some(config.defaults.subscriptions.clone()),
		"REDLIB_DEFAULT_FILTERS" => Some(config.defaults.filters.clone()),
		"REDLIB_DEFAULT_DISABLE_VISIT_REDDIT_CONFIRMATION" => Some(bool_setting(config.defaults.disable_visit_reddit_confirmation)),
		"REDLIB_BANNER" => Some(config.instance.banner.clone()),
		"REDLIB_ROBOTS_DISABLE_INDEXING" => Some(bool_setting(config.instance.robots_disable_indexing)),
		"REDLIB_PUSHSHIFT_FRONTEND" => Some(config.instance.pushshift_frontend.clone()),
		"REDLIB_ENABLE_RSS" => Some(bool_setting(config.instance.enable_rss)),
		"REDLIB_FULL_URL" => config.instance.full_url.clone(),
		"REDLIB_DEFAULT_REMOVE_DEFAULT_FEEDS" => Some(bool_setting(config.defaults.remove_default_feeds)),
		"REDLIB_EXTERNAL_MEDIA_DOMAIN" => config.instance.external_media_domain.clone(),
		"REDLIB_REDDIT_SESSION_COUNT" => Some(config.reddit.session_count.to_string()),
		"REDLIB_REDDIT_STARTUP_POLICY" => Some(config.reddit.startup_policy.to_string()),
		"REDLIB_REDDIT_STARTUP_MIN_HEALTHY_SESSIONS" => Some(config.reddit.startup_min_healthy_sessions.to_string()),
		"REDLIB_REDDIT_BACKEND_POLICY" => Some(config.reddit.backend_policy.to_string()),
		"REDLIB_REDDIT_SELECTION_POLICY" => Some(config.reddit.selection_policy.to_string()),
		"REDLIB_REDDIT_BOOTSTRAP_CONCURRENCY" => Some(config.reddit.bootstrap_concurrency.to_string()),
		"REDLIB_REDDIT_RESERVE_REMAINING_PER_SESSION" => Some(config.reddit.reserve_remaining_per_session.to_string()),
		"REDLIB_REDDIT_REFRESH_MARGIN_SECONDS" => Some(config.reddit.refresh_margin.as_secs().to_string()),
		"REDLIB_REDDIT_REFRESH_JITTER_SECONDS" => Some(config.reddit.refresh_jitter.as_secs().to_string()),
		"REDLIB_REDDIT_REQUEST_TIMEOUT_SECONDS" => Some(config.reddit.request_timeout.as_secs().to_string()),
		"REDLIB_REDDIT_MAX_ATTEMPTS_PER_API_REQUEST" => Some(config.reddit.max_attempts_per_api_request.to_string()),
		"REDLIB_REDDIT_QUOTA_EXHAUSTION_POLICY" => Some(config.reddit.quota_exhaustion_policy.to_string()),
		_ => None,
	}
}

/// Retrieves setting from typed configuration.
pub fn get_setting(name: &str) -> Option<String> {
	get_setting_from_config(name, &CONFIG)
}

#[cfg(test)]
mod tests {
	use super::*;
	use {sealed_test::prelude::*, std::fs::write};

	#[test]
	fn test_deserialize() {
		// Must handle empty input
		let result = toml::from_str::<Config>("");
		assert!(result.is_ok(), "Error: {}", result.unwrap_err());
	}

	#[test]
	#[sealed_test(env = [("REDLIB_SFW_ONLY", "on")])]
	fn test_env_var() {
		assert!(crate::utils::sfw_only())
	}

	#[test]
	#[sealed_test]
	fn test_config() {
		let config_to_write = r#"REDLIB_DEFAULT_COMMENT_SORT = "best""#;
		write("redlib.toml", config_to_write).unwrap();
		assert_eq!(get_setting("REDLIB_DEFAULT_COMMENT_SORT"), Some("best".into()));
	}

	#[test]
	#[sealed_test]
	fn test_config_legacy() {
		let config_to_write = r#"LIBREDDIT_DEFAULT_COMMENT_SORT = "best""#;
		write("libreddit.toml", config_to_write).unwrap();
		assert_eq!(get_setting("REDLIB_DEFAULT_COMMENT_SORT"), Some("best".into()));
	}

	#[test]
	#[sealed_test(env = [("LIBREDDIT_SFW_ONLY", "on")])]
	fn test_env_var_legacy() {
		assert!(crate::utils::sfw_only())
	}

	#[test]
	#[sealed_test(env = [("REDLIB_DEFAULT_COMMENT_SORT", "top")])]
	fn test_env_config_precedence() {
		let config_to_write = r#"REDLIB_DEFAULT_COMMENT_SORT = "best""#;
		write("redlib.toml", config_to_write).unwrap();
		assert_eq!(get_setting("REDLIB_DEFAULT_COMMENT_SORT"), Some("top".into()))
	}

	#[test]
	#[sealed_test(env = [("REDLIB_DEFAULT_COMMENT_SORT", "top")])]
	fn test_alt_env_config_precedence() {
		let config_to_write = r#"REDLIB_DEFAULT_COMMENT_SORT = "best""#;
		write("redlib.toml", config_to_write).unwrap();
		assert_eq!(get_setting("REDLIB_DEFAULT_COMMENT_SORT"), Some("top".into()))
	}

	#[test]
	#[sealed_test(env = [("REDLIB_DEFAULT_SUBSCRIPTIONS", "news+bestof")])]
	fn test_default_subscriptions() {
		assert_eq!(get_setting("REDLIB_DEFAULT_SUBSCRIPTIONS"), Some("news+bestof".into()));
	}

	#[test]
	#[sealed_test(env = [("REDLIB_DEFAULT_FILTERS", "news+bestof")])]
	fn test_default_filters() {
		assert_eq!(get_setting("REDLIB_DEFAULT_FILTERS"), Some("news+bestof".into()));
	}

	#[test]
	#[sealed_test]
	fn test_pushshift() {
		let config_to_write = r#"REDLIB_PUSHSHIFT_FRONTEND = "https://api.pushshift.io""#;
		write("redlib.toml", config_to_write).unwrap();
		assert!(get_setting("REDLIB_PUSHSHIFT_FRONTEND").is_some());
		assert_eq!(get_setting("REDLIB_PUSHSHIFT_FRONTEND"), Some("https://api.pushshift.io".into()));
	}
}
