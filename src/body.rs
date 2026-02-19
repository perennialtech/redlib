use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};

pub type Body = BoxBody<Bytes, String>;

pub fn full(data: impl Into<Bytes>) -> Body {
	Full::new(data.into()).map_err(|never| match never {}).boxed()
}

pub fn empty() -> Body {
	Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}
