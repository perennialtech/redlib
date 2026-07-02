use crate::{
	config::{Config, CONFIG},
	server::RequestExt,
	utils::{ErrorTemplate, Preferences},
};
use askama::Template;
use build_html::{Container, Html, HtmlContainer, Table};
use hyper::{http::Error, Body, Request, Response};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use time::OffsetDateTime;

/// This is the local static that is initialized at runtime (technically at
/// the first request to the info endpoint) and contains the data
/// retrieved from the info endpoint.
pub static INSTANCE_INFO: LazyLock<InstanceInfo> = LazyLock::new(InstanceInfo::new);

/// Handles instance info endpoint
pub async fn instance_info(req: Request<Body>) -> Result<Response<Body>, String> {
	// This will retrieve the extension given, or create a new string - which will
	// simply become the last option, an HTML page.
	let extension = req.param("extension").unwrap_or_default();
	let response = match extension.as_str() {
		"yaml" | "yml" => info_yaml(),
		"txt" => info_txt(),
		"json" => info_json(),
		"html" | "" => info_html(&req),
		_ => {
			let error = ErrorTemplate {
				msg: "Error: Invalid info extension".into(),
				prefs: Preferences::new(&req),
				url: req.uri().to_string(),
			}
			.render()
			.unwrap();
			Response::builder().status(404).header("content-type", "text/html; charset=utf-8").body(error.into())
		}
	};
	response.map_err(|err| format!("{err}"))
}

fn info_json() -> Result<Response<Body>, Error> {
	if let Ok(body) = serde_json::to_string(&*INSTANCE_INFO) {
		Response::builder().status(200).header("content-type", "application/json").body(body.into())
	} else {
		Response::builder()
			.status(500)
			.header("content-type", "text/plain")
			.body(Body::from("Error serializing JSON"))
	}
}

fn info_yaml() -> Result<Response<Body>, Error> {
	if let Ok(body) = serde_yaml::to_string(&*INSTANCE_INFO) {
		// We can use `application/yaml` as media type, though there is no guarantee
		// that browsers will honor it. But we'll do it anyway. See:
		// https://github.com/ietf-wg-httpapi/mediatypes/blob/main/draft-ietf-httpapi-yaml-mediatypes.md#media-type-applicationyaml-application-yaml
		Response::builder().status(200).header("content-type", "application/yaml").body(body.into())
	} else {
		Response::builder()
			.status(500)
			.header("content-type", "text/plain")
			.body(Body::from("Error serializing YAML."))
	}
}

fn info_txt() -> Result<Response<Body>, Error> {
	Response::builder()
		.status(200)
		.header("content-type", "text/plain")
		.body(Body::from(INSTANCE_INFO.to_string(&StringType::Raw)))
}
fn info_html(req: &Request<Body>) -> Result<Response<Body>, Error> {
	let message = MessageTemplate {
		title: String::from("Instance information"),
		body: INSTANCE_INFO.to_string(&StringType::Html),
		prefs: Preferences::new(req),
		url: req.uri().to_string(),
	}
	.render()
	.unwrap();
	Response::builder().status(200).header("content-type", "text/html; charset=utf8").body(Body::from(message))
}
#[derive(Serialize, Deserialize, Default)]
pub struct InstanceInfo {
	package_name: String,
	crate_version: String,
	pub git_commit: String,
	deploy_date: String,
	compile_mode: String,
	deploy_unix_ts: i64,
	config: Config,
}

impl InstanceInfo {
	pub fn new() -> Self {
		Self {
			package_name: env!("CARGO_PKG_NAME").to_string(),
			crate_version: env!("CARGO_PKG_VERSION").to_string(),
			git_commit: env!("GIT_HASH").to_string(),
			deploy_date: OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc()).to_string(),
			#[cfg(debug_assertions)]
			compile_mode: "Debug".into(),
			#[cfg(not(debug_assertions))]
			compile_mode: "Release".into(),
			deploy_unix_ts: OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc()).unix_timestamp(),
			config: CONFIG.clone(),
		}
	}
	fn to_table(&self) -> String {
		let mut container = Container::default();
		let convert = |o: &Option<String>| -> String { o.clone().unwrap_or_else(|| "<span class=\"unset\"><i>Unset</i></span>".to_owned()) };
		let convert_str = |s: &str| -> String {
			if s.is_empty() {
				"<span class=\"unset\"><i>Unset</i></span>".to_owned()
			} else {
				s.to_owned()
			}
		};
		let convert_bool = |b: bool| -> String {
			if b {
				"true".to_owned()
			} else {
				"false".to_owned()
			}
		};
		if !self.config.instance.banner.is_empty() {
			container.add_header(3, "Instance banner");
			container.add_raw("<br />");
			container.add_paragraph(&self.config.instance.banner);
			container.add_raw("<br />");
		}
		container.add_table(
			Table::from([
				["Package name", &self.package_name],
				["Crate version", &self.crate_version],
				["Git commit", &self.git_commit],
				["Deploy date", &self.deploy_date],
				["Deploy timestamp", &self.deploy_unix_ts.to_string()],
				["Compile mode", &self.compile_mode],
				["SFW only", &convert_bool(self.config.instance.sfw_only)],
				["Pushshift frontend", &convert_str(&self.config.instance.pushshift_frontend)],
				["RSS enabled", &convert_bool(self.config.instance.enable_rss)],
				["Full URL", &convert(&self.config.instance.full_url)],
				["Remove default feeds", &convert_bool(self.config.defaults.remove_default_feeds)],
				["External media domain", &convert(&self.config.instance.external_media_domain)],
				//TODO: fallback to crate::config::DEFAULT_PUSHSHIFT_FRONTEND
			])
			.with_header_row(["Settings"]),
		);
		container.add_raw("<br />");
		container.add_table(
			Table::from([
				["Hide awards", &convert_bool(self.config.defaults.hide_awards)],
				["Hide score", &convert_bool(self.config.defaults.hide_score)],
				["Theme", &convert_str(&self.config.defaults.theme)],
				["Front page", &convert_str(&self.config.defaults.front_page)],
				["Layout", &convert_str(&self.config.defaults.layout)],
				["Wide", &convert_bool(self.config.defaults.wide)],
				["Comment sort", &convert_str(&self.config.defaults.comment_sort)],
				["Post sort", &convert_str(&self.config.defaults.post_sort)],
				["Blur Spoiler", &convert_bool(self.config.defaults.blur_spoiler)],
				["Show NSFW", &convert_bool(self.config.defaults.show_nsfw)],
				["Blur NSFW", &convert_bool(self.config.defaults.blur_nsfw)],
				["Use HLS", &convert_bool(self.config.defaults.use_hls)],
				["Hide HLS notification", &convert_bool(self.config.defaults.hide_hls_notification)],
				["Subscriptions", &convert_str(&self.config.defaults.subscriptions)],
				["Filters", &convert_str(&self.config.defaults.filters)],
			])
			.with_header_row(["Default preferences"]),
		);
		container.to_html_string().replace("<th>", "<th colspan=\"2\">")
	}
	fn to_string(&self, string_type: &StringType) -> String {
		match string_type {
			StringType::Raw => {
				format!(
					"Package name: {}\n
				Crate version: {}\n
                Git commit: {}\n
                Deploy date: {}\n
                Deploy timestamp: {}\n
                Compile mode: {}\n
				SFW only: {:?}\n
				Pushshift frontend: {:?}\n
				RSS enabled: {:?}\n
				Full URL: {:?}\n
				Remove default feeds: {:?}\n
				External media domain: {:?}\n
                Config:\n
                    Banner: {:?}\n
                    Hide awards: {:?}\n
                    Hide score: {:?}\n
                    Default theme: {:?}\n
                    Default front page: {:?}\n
                    Default layout: {:?}\n
                    Default wide: {:?}\n
                    Default comment sort: {:?}\n
                    Default post sort: {:?}\n
					Default blur Spoiler: {:?}\n
                    Default show NSFW: {:?}\n
                    Default blur NSFW: {:?}\n
                    Default use HLS: {:?}\n
                    Default hide HLS notification: {:?}\n
                    Default subscriptions: {:?}\n
                    Default filters: {:?}\n",
					self.package_name,
					self.crate_version,
					self.git_commit,
					self.deploy_date,
					self.deploy_unix_ts,
					self.compile_mode,
					self.config.instance.sfw_only,
					self.config.instance.pushshift_frontend,
					self.config.instance.enable_rss,
					self.config.instance.full_url,
					self.config.defaults.remove_default_feeds,
					self.config.instance.external_media_domain,
					self.config.instance.banner,
					self.config.defaults.hide_awards,
					self.config.defaults.hide_score,
					self.config.defaults.theme,
					self.config.defaults.front_page,
					self.config.defaults.layout,
					self.config.defaults.wide,
					self.config.defaults.comment_sort,
					self.config.defaults.post_sort,
					self.config.defaults.blur_spoiler,
					self.config.defaults.show_nsfw,
					self.config.defaults.blur_nsfw,
					self.config.defaults.use_hls,
					self.config.defaults.hide_hls_notification,
					self.config.defaults.subscriptions,
					self.config.defaults.filters,
				)
			}
			StringType::Html => self.to_table(),
		}
	}
}
enum StringType {
	Raw,
	Html,
}
#[derive(Template)]
#[template(path = "message.html")]
struct MessageTemplate {
	title: String,
	body: String,
	prefs: Preferences,
	url: String,
}
