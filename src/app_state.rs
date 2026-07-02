use crate::{
	config::Config,
	reddit::{transport::build_external_http_client, RedditGateway},
};
use std::sync::Arc;
use wreq::Client as WreqClient;

#[derive(Clone)]
pub struct AppState {
	pub config: Arc<Config>,
	pub reddit: Arc<RedditGateway>,
	pub external_http: WreqClient,
}

impl AppState {
	pub async fn new(config: Config) -> Result<Self, crate::reddit::ApiError> {
		let config = Arc::new(config);
		let external_http = build_external_http_client();
		let reddit = Arc::new(RedditGateway::new(config.reddit.clone()).await?);

		Ok(Self {
			config,
			reddit,
			external_http,
		})
	}
}
