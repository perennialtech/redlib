use log::info;
use wreq::{redirect::Policy, Client as WreqClient, EmulationFactory};
use wreq_util::{Emulation, EmulationOS, EmulationOption};

pub fn build_reddit_transport() -> WreqClient {
	let emulation = [Emulation::Chrome145, Emulation::Firefox147];
	let emulation_os = [EmulationOS::Android, EmulationOS::Windows];

	let rand = fastrand::usize(..);
	let emulation = EmulationOption::builder()
		.emulation(emulation[rand % emulation.len()])
		.emulation_os(emulation_os[rand % emulation_os.len()])
		.build()
		.emulation();

	info!("Building Reddit session transport with emulation {:?}", emulation);
	WreqClient::builder()
		.emulation(emulation)
		.redirect(Policy::none())
		.build()
		.expect("Reddit session transport should build")
}

pub fn build_media_http_client() -> WreqClient {
	WreqClient::builder().redirect(Policy::none()).build().expect("media HTTP client should build")
}

pub fn build_external_http_client() -> WreqClient {
	WreqClient::builder().build().expect("external HTTP client should build")
}
