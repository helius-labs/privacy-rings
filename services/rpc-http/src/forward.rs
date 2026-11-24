//! Forwards a call to the upstream a resolver names and serves every other
//! request locally.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Bytes,
    header::{HeaderName, CONTENT_TYPE, RETRY_AFTER},
    http::request::Parts,
    Method, StatusCode,
};
use jsonrpsee::{
    core::BoxError,
    server::{HttpBody, HttpRequest, HttpResponse},
    types::error::ErrorCode,
};
use thiserror::Error;
use tokio::sync::Semaphore;
use tower::{Layer, Service};

use super::{error_response, Call};

static HOPS: HeaderName = HeaderName::from_static("x-spr-hops");
/// A forwarder in front of a forwarder in front of the serving upstream.
const MAX_HOPS: u8 = 2;
static REQUEST_HEADERS: [HeaderName; 3] = [
    CONTENT_TYPE,
    HeaderName::from_static("x-api-key"),
    HeaderName::from_static("x-forwarded-for"),
];
static RESPONSE_HEADERS: [HeaderName; 3] = [
    CONTENT_TYPE,
    RETRY_AFTER,
    HeaderName::from_static("x-helius-metering-units"),
];

/// An http(s) base without query or fragment, request paths append to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamUrl(Arc<str>);

#[derive(Debug, Error)]
pub enum UpstreamUrlError {
    #[error("the upstream URL does not parse")]
    Parse(#[from] url::ParseError),
    #[error("the upstream URL must be http or https")]
    Scheme,
    #[error("the upstream URL takes no query or fragment")]
    QueryOrFragment,
}

impl FromStr for UpstreamUrl {
    type Err = UpstreamUrlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url = url::Url::parse(value)?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(UpstreamUrlError::Scheme);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(UpstreamUrlError::QueryOrFragment);
        }
        Ok(Self(url.as_str().trim_end_matches('/').into()))
    }
}

impl UpstreamUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UpstreamUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub trait Resolve: Send + Sync + 'static {
    /// `method` is `None` unless the request is a POST of one call.
    fn upstream(&self, method: Option<&str>) -> Option<UpstreamUrl>;
}

#[derive(Clone, Copy, Debug)]
pub struct ForwardLimits {
    pub request_bytes: usize,
    pub timeout: Duration,
    /// Requests in the layer at once, local and forwarded.
    pub concurrent: usize,
}

pub struct ForwardLayer<Resolver> {
    forwarder: Arc<Forwarder<Resolver>>,
}

impl<Resolver> ForwardLayer<Resolver> {
    pub fn new(resolver: Resolver, limits: ForwardLimits) -> Result<Self, reqwest::Error> {
        Ok(Self {
            forwarder: Arc::new(Forwarder {
                resolver,
                // A followed redirect or a retry would replay a signed call.
                http: reqwest::Client::builder()
                    .timeout(limits.timeout)
                    .redirect(reqwest::redirect::Policy::none())
                    .retry(reqwest::retry::never())
                    .build()?,
                admitted: Semaphore::new(limits.concurrent),
                limits,
            }),
        })
    }
}

impl<Resolver> Clone for ForwardLayer<Resolver> {
    fn clone(&self) -> Self {
        Self {
            forwarder: self.forwarder.clone(),
        }
    }
}

impl<Inner, Resolver> Layer<Inner> for ForwardLayer<Resolver> {
    type Service = Forward<Inner, Resolver>;

    fn layer(&self, inner: Inner) -> Self::Service {
        Forward {
            inner,
            forwarder: self.forwarder.clone(),
        }
    }
}

pub struct Forward<Inner, Resolver> {
    inner: Inner,
    forwarder: Arc<Forwarder<Resolver>>,
}

impl<Inner: Clone, Resolver> Clone for Forward<Inner, Resolver> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            forwarder: self.forwarder.clone(),
        }
    }
}

impl<Inner, Resolver> Service<HttpRequest> for Forward<Inner, Resolver>
where
    Inner: Service<HttpRequest, Response = HttpResponse> + Clone + Send + 'static,
    Inner::Error: Into<BoxError> + 'static,
    Inner::Future: Send + 'static,
    Resolver: Resolve,
{
    type Response = HttpResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: HttpRequest) -> Self::Future {
        // The service polled ready serves this call, its clone serves the next.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let forwarder = self.forwarder.clone();
        Box::pin(async move {
            // The server counts a call only after this layer, a forwarded call never reaches it.
            let Ok(_admitted) = forwarder.admitted.try_acquire() else {
                return Ok(error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    None,
                    ErrorCode::ServerIsBusy,
                    ErrorCode::ServerIsBusy.message(),
                ));
            };
            let (parts, body) = request.into_parts();
            let Ok(collected) = Limited::new(body, forwarder.limits.request_bytes)
                .collect()
                .await
            else {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    None,
                    ErrorCode::InvalidRequest,
                    "unreadable request body",
                ));
            };
            let body = collected.to_bytes();
            let upstream = {
                let call = (parts.method == Method::POST)
                    .then(|| serde_json::from_slice::<Call<'_>>(&body).ok())
                    .flatten();
                forwarder
                    .resolver
                    .upstream(call.as_ref().map(|call| call.method.as_ref()))
            };
            match upstream {
                Some(upstream) => Ok(forwarder.forward(upstream, parts, body).await),
                None => inner
                    .call(HttpRequest::from_parts(
                        parts,
                        HttpBody::new(Full::new(body)),
                    ))
                    .await
                    .map_err(Into::into),
            }
        })
    }
}

struct Forwarder<Resolver> {
    resolver: Resolver,
    http: reqwest::Client,
    admitted: Semaphore,
    limits: ForwardLimits,
}

impl<Resolver> Forwarder<Resolver> {
    async fn forward(&self, upstream: UpstreamUrl, parts: Parts, body: Bytes) -> HttpResponse {
        let hops = match parts.headers.get(&HOPS) {
            None => 0,
            Some(value) => value
                .to_str()
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(MAX_HOPS),
        };
        if hops >= MAX_HOPS {
            return error_response(
                StatusCode::LOOP_DETECTED,
                None,
                ErrorCode::InternalError,
                "forwarding loop",
            );
        }
        match self.send(&upstream, parts, body, hops + 1).await {
            Ok(response) => response,
            Err(error) => {
                log::warn!("upstream {upstream} did not answer ({error})");
                error_response(
                    StatusCode::BAD_GATEWAY,
                    None,
                    ErrorCode::InternalError,
                    "the upstream did not answer",
                )
            }
        }
    }

    async fn send(
        &self,
        upstream: &UpstreamUrl,
        parts: Parts,
        body: Bytes,
        hops: u8,
    ) -> Result<HttpResponse, reqwest::Error> {
        let path = parts.uri.path_and_query().map_or("/", |path| path.as_str());
        let mut request = self
            .http
            .request(parts.method, format!("{upstream}{path}"))
            .header(&HOPS, u16::from(hops))
            .body(body);
        for name in &REQUEST_HEADERS {
            if let Some(value) = parts.headers.get(name) {
                request = request.header(name, value);
            }
        }
        // The query may carry an API key.
        let answer = request.send().await.map_err(reqwest::Error::without_url)?;
        let (status, headers) = (answer.status(), answer.headers().clone());
        let mut response = HttpResponse::new(HttpBody::new(reqwest::Body::from(answer)));
        *response.status_mut() = status;
        for name in &RESPONSE_HEADERS {
            if let Some(value) = headers.get(name) {
                response.headers_mut().insert(name, value.clone());
            }
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use jsonrpsee::{
        server::{ServerBuilder, ServerHandle},
        RpcModule,
    };
    use tower::{service_fn, ServiceExt};

    use super::*;

    const LIMITS: ForwardLimits = ForwardLimits {
        request_bytes: 1024,
        timeout: Duration::from_secs(5),
        concurrent: 8,
    };

    struct Only(&'static str, UpstreamUrl);

    impl Resolve for Only {
        fn upstream(&self, method: Option<&str>) -> Option<UpstreamUrl> {
            (method? == self.0).then(|| self.1.clone())
        }
    }

    #[derive(Clone)]
    struct ReceivedHops(Option<String>);

    static UNITS: HeaderName = HeaderName::from_static("x-helius-metering-units");

    /// Answers `ringStatus` with the hop count it received.
    async fn upstream() -> (UpstreamUrl, ServerHandle) {
        let mut module = RpcModule::new(());
        module
            .register_method("ringStatus", |_, _, extensions| {
                extensions
                    .get::<ReceivedHops>()
                    .and_then(|hops| hops.0.clone())
            })
            .unwrap();
        let server = ServerBuilder::default()
            .set_http_middleware(
                tower::ServiceBuilder::new()
                    .map_request(|mut request: HttpRequest| {
                        let hops = request
                            .headers()
                            .get(&HOPS)
                            .and_then(|hops| hops.to_str().ok());
                        let hops = ReceivedHops(hops.map(str::to_owned));
                        request.extensions_mut().insert(hops);
                        request
                    })
                    .map_response(|mut response: HttpResponse| {
                        response.headers_mut().insert(&UNITS, 3.into());
                        response
                    }),
            )
            .build(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (url.parse().unwrap(), server.start(module))
    }

    fn service(
        url: UpstreamUrl,
    ) -> impl Service<HttpRequest, Response = HttpResponse, Error = BoxError> + Clone {
        limited(url, LIMITS)
    }

    fn limited(
        url: UpstreamUrl,
        limits: ForwardLimits,
    ) -> impl Service<HttpRequest, Response = HttpResponse, Error = BoxError> + Clone {
        ForwardLayer::new(Only("ringStatus", url), limits)
            .unwrap()
            .layer(service_fn(|_request: HttpRequest| async {
                Ok::<_, BoxError>(HttpResponse::new(HttpBody::from("local")))
            }))
    }

    fn call(method: &str) -> hyper::http::request::Builder {
        HttpRequest::post(format!("/v1/spr/{method}?api-key=key"))
            .header(CONTENT_TYPE, "application/json")
            .extension(format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#))
    }

    async fn answer(
        service: impl Service<HttpRequest, Response = HttpResponse, Error = BoxError>,
        request: hyper::http::request::Builder,
    ) -> (StatusCode, String) {
        let body = request.extensions_ref().unwrap().get::<String>().cloned();
        let request = request
            .body(HttpBody::from(body.unwrap_or_default()))
            .unwrap();
        let response = service.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn a_resolved_call_reaches_its_upstream_and_every_other_request_stays_local() {
        let (url, server) = upstream().await;
        let service = service(url);

        let (status, body) = answer(service.clone(), call("ringStatus")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#""result":"1""#), "{body}");

        for request in [
            call("getMerkleProofs"),
            HttpRequest::get("/ringStatus"),
            HttpRequest::post("/").extension(r#"[{"method":"ringStatus","id":1}]"#.to_owned()),
        ] {
            assert_eq!(answer(service.clone(), request).await.1, "local");
        }
        server.stop().unwrap();
    }

    #[tokio::test]
    async fn a_forwarded_answer_keeps_its_metering_units() {
        let (url, server) = upstream().await;
        let request = call("ringStatus").body(HttpBody::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"ringStatus"}"#,
        ));
        let response = service(url).oneshot(request.unwrap()).await.unwrap();
        assert_eq!(response.headers()[&UNITS], "3");
        server.stop().unwrap();
    }

    #[tokio::test]
    async fn a_call_above_the_concurrency_limit_is_refused_local_or_forwarded() {
        let (url, server) = upstream().await;
        let limits = ForwardLimits {
            concurrent: 0,
            ..LIMITS
        };
        for method in ["ringStatus", "getMerkleProofs"] {
            let (status, body) = answer(limited(url.clone(), limits), call(method)).await;
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{method}");
            assert!(body.contains("-32009"), "{body}");
        }
        server.stop().unwrap();
    }

    #[tokio::test]
    async fn a_call_at_the_hop_limit_is_refused_before_it_leaves() {
        let (url, server) = upstream().await;
        for hops in ["2", "200", "not a count"] {
            let (status, body) =
                answer(service(url.clone()), call("ringStatus").header(&HOPS, hops)).await;
            assert_eq!(status, StatusCode::LOOP_DETECTED, "{hops}");
            assert!(body.contains("-32603"), "{body}");
        }
        let (_, body) = answer(service(url), call("ringStatus").header(&HOPS, "1")).await;
        assert!(body.contains(r#""result":"2""#), "{body}");
        server.stop().unwrap();
    }

    #[tokio::test]
    async fn a_silent_upstream_answers_bad_gateway() {
        let (url, server) = upstream().await;
        server.stop().unwrap();
        server.stopped().await;
        let (status, body) = answer(service(url), call("ringStatus")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.contains("-32603"), "{body}");
    }

    #[test]
    fn an_upstream_url_is_an_http_base() {
        assert_eq!(
            "http://ring.internal:8785/"
                .parse::<UpstreamUrl>()
                .unwrap()
                .to_string(),
            "http://ring.internal:8785"
        );
        for refused in [
            "ftp://ring",
            "http://ring/?api-key=1",
            "http://ring/#a",
            "ring",
        ] {
            assert!(refused.parse::<UpstreamUrl>().is_err(), "{refused}");
        }
    }
}
