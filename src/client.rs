use crate::reddit::{transport::build_external_http_client, RedditGateway};
use hyper::{Body, Request as HyperRequest, Response as HyperResponse};
use serde_json::Value;
use std::{
	result::Result,
	sync::{Arc, LazyLock, OnceLock},
};
use wreq::Client as WreqClient;

pub use crate::reddit::{ApiError, ApiErrorKind};

pub static CLIENT: LazyLock<WreqClient> = LazyLock::new(build_external_http_client);

static REDDIT_GATEWAY: OnceLock<Arc<RedditGateway>> = OnceLock::new();

pub fn install_reddit_gateway(gateway: Arc<RedditGateway>) {
	let _ = REDDIT_GATEWAY.set(gateway);
}

fn reddit() -> Arc<RedditGateway> {
	REDDIT_GATEWAY.get().expect("RedditGateway must be installed during application startup").clone()
}

pub async fn canonical_path(path: String, tries: i8) -> Result<Option<String>, String> {
	let tries = u8::try_from(tries.max(0)).unwrap_or(0);
	reddit().canonical_path(path, tries).await.map_err(|err| err.message)
}

pub async fn proxy(req: HyperRequest<Body>, format: &str) -> Result<HyperResponse<Body>, String> {
	reddit().proxy_media(req, format).await
}

pub async fn json(path: String, quarantine: bool) -> Result<Value, ApiError> {
	reddit().json(path, quarantine).await
}

pub async fn rate_limit_check() -> Result<(), String> {
	reddit().health_check(false).await.map_err(|err| err.message)
}

#[cfg(test)]
mod tests {
	use super::*;
	use {crate::config::get_setting, sealed_test::prelude::*};

	const POPULAR_URL: &str = "/r/popular/hot.json?&raw_json=1&geo_filter=GLOBAL";

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
		assert_eq!(link.unwrap_err().message, "private");
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_banned_sub() {
		let link = json("/r/aaa/about.json?raw_json=1".into(), true).await;
		assert!(link.is_err());
		assert_eq!(link.unwrap_err().message, "banned");
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_gated_sub() {
		// quarantine to false to specifically catch when we _don't_ catch it
		let link = json("/r/drugs/about.json?raw_json=1".into(), false).await;
		assert!(link.is_err());
		assert_eq!(link.unwrap_err().message, "gated");
	}
}
