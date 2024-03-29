use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Json, MatchedPath},
    http::Method,
    routing::{get, post, put, Router},
};
// use axum_macros::debug_handler;
use envy;
use hyper::HeaderMap;
use opentelemetry_otlp::{self};
use opentelemetry_sdk::resource::{
    EnvResourceDetector, SdkProvidedResourceDetector, TelemetryResourceDetector,
};
use opentelemetry_sdk::Resource;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower_http::classify::StatusInRangeAsFailures;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tower_otel_http_metrics;
use tracing::{info, instrument};
use tracing::level_filters::LevelFilter;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::Registry;

const SERVICE_NAME: &str = "echo-server";

#[derive(Deserialize)]
struct Config {
    #[serde(default = "file_exporter_enabled")]
    file_logs_traces_exporter_enabled: bool,
    #[serde(default = "std_stream_exporter_enabled")]
    std_stream_logs_traces_exporter_enabled: bool,
    #[serde(default = "otel_collector_exporter_enabled")]
    otel_collector_logs_traces_exporter_enabled: bool,
    #[serde(default = "otel_collector_exporter_enabled")]
    otel_collector_metrics_exporter_enabled: bool,
}

fn file_exporter_enabled() -> bool {
    false
}

fn std_stream_exporter_enabled() -> bool {
    false
}

fn otel_collector_exporter_enabled() -> bool {
    true
}

fn init_otel_resource() -> Resource {
    let otlp_resource_detected = Resource::from_detectors(
        Duration::from_secs(3),
        vec![
            Box::new(SdkProvidedResourceDetector),
            Box::new(EnvResourceDetector::new()),
            Box::new(TelemetryResourceDetector),
        ],
    );
    let otlp_resource_override = Resource::new(vec![
        opentelemetry_semantic_conventions::resource::SERVICE_NAME.string(SERVICE_NAME),
    ]);
    otlp_resource_detected.merge(&otlp_resource_override)
}

fn init_otel_subscribers() {
    let config = envy::from_env::<Config>().unwrap();

    let mut file_writer_layer = None;
    if config.file_logs_traces_exporter_enabled {
        // file writer layer to collect all levels of logs, mostly useful for debugging the logging setup
        let file_appender = tracing_appender::rolling::minutely("./logs", "trace");
        let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);
        file_writer_layer = Option::from(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(file_writer),
        );
    }

    let mut std_stream_log_subscriber_layer = None;
    if config.std_stream_logs_traces_exporter_enabled {
        // stdout/stderr log layer for non-tracing logs to be collected into ElasticSearch or similar
        let _std_stream_log_subscriber_layer =
            BunyanFormattingLayer::new(SERVICE_NAME.into(), std::io::stderr)
                .with_filter(LevelFilter::INFO);
        std_stream_log_subscriber_layer = Option::from(_std_stream_log_subscriber_layer);
    }

    let mut otel_log_trace_subscriber_layer = None;
    if config.otel_collector_logs_traces_exporter_enabled {
        // init otel tracing propogator; see more about opentelemetry propagators here:
        // https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/context/api-propagators.md
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );

        // init otel tracing pipeline
        // https://docs.rs/opentelemetry-otlp/latest/opentelemetry_otlp/#kitchen-sink-full-configuration
        // this pipeline will log connection errors to stderr if it cannot reach the collector endpoint
        let otel_trace_pipeline = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(opentelemetry_otlp::new_exporter().tonic()) // default endpoint http://localhost:4317
            .with_trace_config(
                opentelemetry_sdk::trace::config().with_resource(init_otel_resource()),
            );

        // init otel tracer
        // use this stdout pipeline instead to debug or view the opentelemetry data without a collector
        // let otel_tracer = opentelemetry_stdout::new_pipeline().install_simple();
        let otel_tracer = otel_trace_pipeline
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .unwrap();
        otel_log_trace_subscriber_layer =
            Option::from(tracing_opentelemetry::layer().with_tracer(otel_tracer));
    }

    let mut otel_metrics_subscriber_layer = None;
    if config.otel_collector_metrics_exporter_enabled {
        // init otel metrics pipeline
        // https://docs.rs/opentelemetry-otlp/latest/opentelemetry_otlp/#kitchen-sink-full-configuration
        // this configuration interface is annoyingly slightly different from the tracing one
        let otel_metrics_pipeline = opentelemetry_otlp::new_pipeline()
            .metrics(opentelemetry_sdk::runtime::Tokio)
            .with_exporter(opentelemetry_otlp::new_exporter().tonic()) // default endpoint http://localhost:4317
            .with_resource(init_otel_resource())
            .build()
            .unwrap();
        // the call to build() registers the global meter provider so we do not need to
        // register a subscriber layer the way we do with the tracing/logging SDK,
        // but we can do it here for consistency's sake and maybe one day the OTEL SDKs
        // will have more consistent configuration interfaces
        otel_metrics_subscriber_layer = Option::from(tracing_opentelemetry::MetricsLayer::new(
            otel_metrics_pipeline,
        ));
    }

    let telemetry_subscriber = Registry::default()
        .with(file_writer_layer)
        .with(JsonStorageLayer) // stores fields across spans for the bunyan formatter
        .with(std_stream_log_subscriber_layer)
        .with(otel_log_trace_subscriber_layer)
        .with(otel_metrics_subscriber_layer);
    tracing::subscriber::set_global_default(telemetry_subscriber).unwrap();
}

#[tokio::main]
async fn main() {
    init_otel_subscribers();

    // init our otel metrics middleware
    let global_meter = opentelemetry_api::global::meter(Cow::from(SERVICE_NAME));
    let otel_metrics_service_layer = tower_otel_http_metrics::HTTPMetricsLayerBuilder::new()
        .with_meter(global_meter)
        .build()
        .unwrap();

    // init CORS layer
    let cors = CorsLayer::permissive();

    let app = Router::new()
        .route("/", get(echo))
        .route("/", post(echo))
        .route("/", put(echo))
        .route("/json", get(echo_json))
        .route("/json", post(echo_json))
        .route("/json", put(echo_json))
        .layer(cors)
        .layer(TraceLayer::new(
            // by default the tower http trace layer only classifies 5xx errors as failures
            StatusInRangeAsFailures::new(400..=599).into_make_classifier(),
        ))
        .layer(otel_metrics_service_layer);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:5000").await.unwrap();
    info!("starting {}...", SERVICE_NAME);

    let server = axum::serve(listener, app);

    if let Err(err) = server.await {
        eprintln!("server error: {}", err);
    }
}

#[instrument(skip(headers, bytes))]
pub async fn echo(
    matched_path: MatchedPath,
    method: Method,
    headers: HeaderMap,
    bytes: Bytes,
) -> Bytes {
    let parsed_req_headers = parse_request_headers(headers);
    // method and headers get logged by the instrument macro; this is just an example
    info!(
        request.endpoint = String::from(matched_path.as_str()),
        request.method = %method,
        request.headers = ?parsed_req_headers,
        "parsed request headers",
    );
    bytes
}

#[derive(Serialize, Debug)]
struct EchoJSONResponse {
    method: String,
    headers: HashMap<String, String>,
    body: Value,
}

#[instrument(skip(headers, body))]
async fn echo_json(
    matched_path: MatchedPath,
    method: Method,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<EchoJSONResponse> {
    let req_method = method.to_string();
    let parsed_req_headers = parse_request_headers(headers);
    // method and headers get logged by the instrument macro; this is just an example
    info!(
        request.endpoint = String::from(matched_path.as_str()),
        request.method = req_method,
        request.headers = ?parsed_req_headers,
        "parsed request headers",
    );

    let resp_body = EchoJSONResponse {
        method: req_method,
        headers: parsed_req_headers,
        body,
    };

    Json(resp_body)
}

fn parse_request_headers(headers: HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect()
}
