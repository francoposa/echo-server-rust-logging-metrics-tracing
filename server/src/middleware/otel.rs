use axum::body::Body;
#[cfg(feature = "axum")]
use axum::extract::MatchedPath;
use axum::http::Response;
use opentelemetry::global::{self};
use opentelemetry::metrics::Meter;
use opentelemetry::metrics::{Histogram, UpDownCounter};
use opentelemetry::KeyValue;
use opentelemetry_semantic_conventions as semconv;
use pin_project_lite::pin_project;
use std::borrow::Cow;
use std::future::Future;
use std::pin::Pin;
use std::string::String;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use std::{fmt, result::Result};
use tower_layer::Layer;
use tower_service::Service;

const HTTP_SERVER_DURATION_METRIC: &str = semconv::metric::HTTP_SERVER_REQUEST_DURATION;
const HTTP_SERVER_DURATION_UNIT: &str = "s";

const OTEL_DEFAULT_HTTP_SERVER_DURATION_BOUNDS: [f64; 14] = [
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

const HTTP_SERVER_ACTIVE_REQUESTS_METRIC: &str = semconv::metric::HTTP_SERVER_ACTIVE_REQUESTS;
const HTTP_SERVER_ACTIVE_REQUESTS_UNIT: &str = "{request}";

const HTTP_SERVER_REQUEST_BODY_SIZE_METRIC: &str = semconv::metric::HTTP_SERVER_REQUEST_BODY_SIZE;
const HTTP_SERVER_REQUEST_BODY_SIZE_UNIT: &str = "By";

const HTTP_SERVER_RESPONSE_BODY_SIZE_METRIC: &str = semconv::metric::HTTP_SERVER_RESPONSE_BODY_SIZE;
const HTTP_SERVER_RESPONSE_BODY_SIZE_UNIT: &str = "By";

const NETWORK_PROTOCOL_NAME_LABEL: &str = semconv::attribute::NETWORK_PROTOCOL_NAME;
const NETWORK_PROTOCOL_VERSION_LABEL: &str = semconv::attribute::NETWORK_PROTOCOL_VERSION;
const URL_SCHEME_LABEL: &str = semconv::attribute::URL_SCHEME;

const HTTP_REQUEST_METHOD_LABEL: &str = semconv::attribute::HTTP_REQUEST_METHOD;
const HTTP_ROUTE_LABEL: &str = semconv::attribute::HTTP_ROUTE;
const HTTP_RESPONSE_STATUS_CODE_LABEL: &str = semconv::attribute::HTTP_RESPONSE_STATUS_CODE;

/// State scoped to the entire middleware Layer.
struct HTTPLayerState {
    pub server_request_duration: Histogram<f64>,
    pub server_active_requests: UpDownCounter<i64>,
    pub server_request_body_size: Histogram<u64>,
    pub server_response_body_size: Histogram<u64>,
}

#[derive(Clone)]
/// [`Service`] used by [`OTelLayer`]
pub struct OTelService<S> {
    pub(crate) state: Arc<HTTPLayerState>,
    inner_service: S,
}

#[derive(Clone)]
/// [`Layer`] which applies the OTEL HTTP server metrics and tracing middleware
pub struct OTelLayer {
    state: Arc<HTTPLayerState>,
}

impl OTelLayer {
    /// Create a new HTTP layer with default configuration using global providers
    pub fn new() -> Self {
        OTelLayerBuilder::builder().build().unwrap()
    }
}

impl Default for OTelLayer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OTelLayerBuilder {
    meter: Option<Meter>,
    req_dur_bounds: Option<Vec<f64>>,
}

pub struct CfgError {
    #[allow(dead_code)]
    inner: ErrorKind,
}

impl fmt::Display for CfgError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.inner {
            ErrorKind::Other(ref s) => write!(f, "{s}"),
            ErrorKind::Config(ref s) => write!(f, "config error: {s}"),
        }
    }
}

impl std::error::Error for CfgError {}

/// `Result` typedef to use with the `opentelemetry_instrumentation_tower::Error` type
pub type CfgResult<T> = Result<T, CfgError>;

enum ErrorKind {
    #[allow(dead_code)]
    /// Uncategorized
    Other(String),
    #[allow(dead_code)]
    /// Invalid configuration
    Config(String),
}

impl fmt::Debug for CfgError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("opentelemetry_instrumentation_tower::Error")
            .finish()
    }
}

impl OTelLayerBuilder {
    pub fn builder() -> Self {
        OTelLayerBuilder {
            meter: None,
            req_dur_bounds: Some(Vec::from(OTEL_DEFAULT_HTTP_SERVER_DURATION_BOUNDS)),
        }
    }
}

impl OTelLayerBuilder {
    pub fn build(self) -> CfgResult<OTelLayer> {
        let req_dur_bounds = self
            .req_dur_bounds
            .unwrap_or_else(|| Vec::from(OTEL_DEFAULT_HTTP_SERVER_DURATION_BOUNDS));

        let meter: Meter = self
            .meter
            .unwrap_or_else(|| global::meter("opentelemetry-instrumentation-tower"));

        Ok(OTelLayer {
            state: Arc::from(Self::make_state(meter, req_dur_bounds)),
        })
    }

    /// Override the meter used for metrics collection.
    ///
    /// This method exists primarily for testing purposes, allowing tests to inject
    /// a custom meter (e.g., backed by an in-memory exporter) without relying on
    /// global state. Using global providers in tests can cause interference between
    /// concurrent tests.
    ///
    /// In production, the default behavior of using the global meter provider
    /// (via `opentelemetry::global::meter()`) is recommended.
    #[cfg(test)]
    fn with_meter(mut self, meter: Meter) -> Self {
        self.meter = Some(meter);
        self
    }

    fn make_state(meter: Meter, req_dur_bounds: Vec<f64>) -> HTTPLayerState {
        HTTPLayerState {
            server_request_duration: meter
                .f64_histogram(Cow::from(HTTP_SERVER_DURATION_METRIC))
                .with_description("Duration of HTTP server requests.")
                .with_unit(Cow::from(HTTP_SERVER_DURATION_UNIT))
                .with_boundaries(req_dur_bounds)
                .build(),
            server_active_requests: meter
                .i64_up_down_counter(Cow::from(HTTP_SERVER_ACTIVE_REQUESTS_METRIC))
                .with_description("Number of active HTTP server requests.")
                .with_unit(Cow::from(HTTP_SERVER_ACTIVE_REQUESTS_UNIT))
                .build(),
            server_request_body_size: meter
                .u64_histogram(HTTP_SERVER_REQUEST_BODY_SIZE_METRIC)
                .with_description("Size of HTTP server request bodies.")
                .with_unit(HTTP_SERVER_REQUEST_BODY_SIZE_UNIT)
                .build(),
            server_response_body_size: meter
                .u64_histogram(HTTP_SERVER_RESPONSE_BODY_SIZE_METRIC)
                .with_description("Size of HTTP server response bodies.")
                .with_unit(HTTP_SERVER_RESPONSE_BODY_SIZE_UNIT)
                .build(),
        }
    }
}

impl<S> Layer<S> for OTelLayer {
    type Service = OTelService<S>;

    fn layer(&self, service: S) -> Self::Service {
        OTelService {
            state: self.state.clone(),
            inner_service: service,
        }
    }
}

/// Request data extracted before the inner service call.
/// This data is needed for metrics and span finalization after the response is received.
struct RequestData {
    // fields for the metric values
    // https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestduration
    duration_start: Instant,
    // https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestbodysize
    req_body_size: Option<u64>,

    // fields for metric labels
    protocol_name_kv: KeyValue,
    protocol_version_kv: KeyValue,
    url_scheme_kv: KeyValue,
    method_kv: KeyValue,
    route_kv_opt: Option<KeyValue>,

    // Custom attributes from request
    custom_request_attributes: Vec<KeyValue>,
}

pin_project! {
    pub struct OTelResponseFuture<F> {
        #[pin]
        request_data: RequestData,
        #[pin]
        inner_response_future: F,
    }
}

impl<S, Request> Service<Request> for OTelService<S>
where
    S: Service<Request, Response = Response<Body>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = OTelResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_service.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let duration_start = Instant::now();

        OTelResponseFuture {
            request_data: RequestData {
                duration_start,
                req_body_size: None,
                protocol_name_kv: KeyValue::new(NETWORK_PROTOCOL_NAME_LABEL, ""),
                protocol_version_kv: KeyValue::new(NETWORK_PROTOCOL_VERSION_LABEL, ""),
                url_scheme_kv: KeyValue::new(URL_SCHEME_LABEL, ""),
                method_kv: KeyValue::new(HTTP_REQUEST_METHOD_LABEL, ""),
                route_kv_opt: None,
                custom_request_attributes: Vec::new(),
            },
            inner_response_future: self.inner_service.call(request),
        }
    }
}

impl<F, ResBody, E> Future for OTelResponseFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let inner_response = match this.inner_response_future.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(response) => response,
        };

        Poll::Ready(inner_response)
    }
}
