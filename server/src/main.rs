use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Json, MatchedPath};
use axum::http::{HeaderMap, Method};
use axum::routing::{get, post, put, Router};
// use axum_macros::debug_handler;
use envy;
use log::info as log_info;
use opentelemetry::metrics::MeterProvider;
use opentelemetry_appender_log::OpenTelemetryLogBridge;
use opentelemetry_otlp::{self, TonicExporterBuilder, WithExportConfig};
use opentelemetry_sdk::resource::{
    EnvResourceDetector, SdkProvidedResourceDetector, TelemetryResourceDetector,
};
use opentelemetry_sdk::Resource;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::signal;
use tower_http::classify::StatusInRangeAsFailures;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::log::Level;
use tracing::{info as tracing_info, instrument};
use tracing_opentelemetry::layer;
use tracing_subscriber::layer::SubscriberExt;
use {tower_otel_http_metrics, tracing};

const SERVICE_NAME: &str = "echo-server-rust";

#[derive(Deserialize)]
struct Config {
    #[serde(default = "server_addr")]
    server_addr: String,

    #[serde(default = "base_url_path_v0")]
    base_url_path: String,

    #[serde(default = "file_exporter_enabled")]
    file_traces_exporter_enabled: bool,

    #[serde(default = "std_stream_exporter_enabled")]
    std_stream_logs_exporter_enabled: bool,

    #[serde(default = "std_stream_exporter_enabled")]
    std_stream_traces_exporter_enabled: bool,

    #[serde(default = "otel_collector_exporter_enabled")]
    otel_collector_logs_exporter_enabled: bool,

    #[serde(default = "otel_collector_exporter_enabled")]
    otel_collector_traces_exporter_enabled: bool,

    #[serde(default = "otel_collector_exporter_enabled")]
    otel_collector_metrics_exporter_enabled: bool,
}

fn server_addr() -> String {
    String::from("0.0.0.0:8080")
}

fn base_url_path_v0() -> String {
    String::from("/api/v0")
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
    let otlp_resource_override = Resource::new(vec![opentelemetry::KeyValue {
        key: opentelemetry_semantic_conventions::resource::SERVICE_NAME.into(),
        value: SERVICE_NAME.into(),
    }]);
    otlp_resource_detected.merge(&otlp_resource_override)
}

fn init_otel(config: &Config) {
    // ************************************ METRICS ************************************
    if config.otel_collector_metrics_exporter_enabled {
        opentelemetry_otlp::new_pipeline()
            .metrics(opentelemetry_sdk::runtime::Tokio)
            .with_exporter(opentelemetry_otlp::new_exporter().tonic())
            .with_resource(init_otel_resource())
            .build()
            .unwrap();
    }

    // ************************************ LOGS ************************************
    // we have to do this with the lower-level builder methods because the standard  higher-level builder
    // from opentelemetry_otlp::new_pipeline()::logging() does not support multiple exporters / processors
    let provider_builder = opentelemetry_sdk::logs::LoggerProvider::builder();
    let mut provider_builder = provider_builder
        .with_config(opentelemetry_sdk::logs::config().with_resource(init_otel_resource()));

    if config.otel_collector_logs_exporter_enabled {
        let batch_exporter = TonicExporterBuilder::default()
            .with_endpoint("http://localhost:4317") // default is http://localhost:4317; explicit over implicit
            .build_log_exporter()
            .unwrap();
        let batch_processor = opentelemetry_sdk::logs::BatchLogProcessor::builder(
            batch_exporter,
            opentelemetry_sdk::runtime::Tokio,
        )
        .build();
        provider_builder = provider_builder.with_log_processor(batch_processor);
    }

    if config.std_stream_logs_exporter_enabled {
        let simple_exporter = opentelemetry_stdout::LogExporterBuilder::default()
            .with_writer(std::io::stderr())
            .build();
        let simple_processor = opentelemetry_sdk::logs::BatchLogProcessor::builder(
            simple_exporter,
            opentelemetry_sdk::runtime::Tokio,
        )
        .build();
        provider_builder = provider_builder.with_log_processor(simple_processor);
    }

    let provider = provider_builder.build();
    // don't use the return value from set_logger_provider; don't ask me why
    // for some reason it returns the old value that was deregistered from the global
    opentelemetry::global::set_logger_provider(provider);
    // use this to pull down the new logger provider
    let global_logger_provider = opentelemetry::global::logger_provider();
    let otel_log_appender = OpenTelemetryLogBridge::new(&global_logger_provider);
    log::set_boxed_logger(Box::new(otel_log_appender)).unwrap();
    log::set_max_level(Level::Info.to_level_filter());

    // ************************************ TRACES ************************************
    // init otel tracing propogator; see more about opentelemetry propagators here:
    // https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/context/api-propagators.md
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let mut file_writer_layer = None;
    if config.file_traces_exporter_enabled {
        // file writer layer to collect all levels of traces, mostly useful for debugging the tracing setup
        let file_appender = tracing_appender::rolling::minutely("./logs", "trace");
        let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);
        file_writer_layer = Option::from(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(file_writer),
        );
    }

    let mut std_stream_traces_subscriber_layer = None;
    if config.std_stream_traces_exporter_enabled {
        // stdout/stderr layer to collect all levels of traces, mostly useful for debugging the tracing setup
        let _std_stream_log_subscriber_layer = tracing_bunyan_formatter::BunyanFormattingLayer::new(
            SERVICE_NAME.into(),
            std::io::stderr,
        );
        std_stream_traces_subscriber_layer = Option::from(_std_stream_log_subscriber_layer);
    }

    let mut otel_trace_subscriber_layer = None;
    if config.otel_collector_traces_exporter_enabled {
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint("http://localhost:4317"), // default is http://localhost:4317; explicit over implicit
            )
            .with_trace_config(
                opentelemetry_sdk::trace::config().with_resource(init_otel_resource()),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .unwrap();
        otel_trace_subscriber_layer = Option::from(layer().with_tracer(tracer));
    }

    // this is only needed because we optionally want multiple tracing subscribers;
    // otherwise we would only need the opentelemetry_otlp::new_pipeline().tracing() setup
    let telemetry_subscriber = tracing_subscriber::Registry::default()
        .with(file_writer_layer)
        .with(tracing_bunyan_formatter::JsonStorageLayer) // stores fields across spans for the bunyan formatter
        .with(std_stream_traces_subscriber_layer)
        .with(otel_trace_subscriber_layer);
    tracing::subscriber::set_global_default(telemetry_subscriber).unwrap();
}

#[tokio::main]
async fn main() {
    let config = envy::from_env::<Config>().unwrap();

    init_otel(&config);

    // init our otel metrics middleware to record HTTP server metrics
    let global_meter_provider = opentelemetry::global::meter_provider();
    let otel_metrics_service_layer = tower_otel_http_metrics::HTTPMetricsLayerBuilder::new()
        .with_meter(global_meter_provider.meter(Cow::from(SERVICE_NAME)))
        .build()
        .unwrap();

    // init CORS layer
    let cors = CorsLayer::permissive();

    let echo_path = &format!("{}/echo", &config.base_url_path);
    let echo_json_path = &format!("{}/echo/json", &config.base_url_path);
    let app = Router::new()
        .route(echo_path, get(echo))
        .route(echo_path, post(echo))
        .route(echo_path, put(echo))
        .route(echo_json_path, get(echo_json))
        .route(echo_json_path, post(echo_json))
        .route(echo_json_path, put(echo_json))
        .layer(cors)
        .layer(TraceLayer::new(
            // by default the tower http trace layer only classifies 5xx errors as failures
            StatusInRangeAsFailures::new(400..=599).into_make_classifier(),
        ))
        .layer(otel_metrics_service_layer);

    let listener = tokio::net::TcpListener::bind(&config.server_addr)
        .await
        .unwrap();
    println!("starting {} on {}...", SERVICE_NAME, &config.server_addr);

    let server = axum::serve(listener, app);
    let shutdown_handler = server.with_graceful_shutdown(shutdown_signal());

    if let Err(err) = shutdown_handler.await {
        eprintln!("server error: {}", err);
    }

    opentelemetry::global::shutdown_tracer_provider();
    opentelemetry::global::shutdown_logger_provider();
    opentelemetry::global::shutdown_logger_provider();
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
    println!("ctrl-c received, shutting down.");
}

#[instrument(level = "trace", skip(bytes))]
pub async fn echo(
    matched_path: MatchedPath,
    method: Method,
    headers: HeaderMap,
    bytes: Bytes,
) -> Bytes {
    let parsed_req_headers = parse_request_headers(headers);
    // method and headers get recorded on the trace by the instrument macro; this is just an example
    // see https://docs.rs/tracing/latest/tracing/#recording-fields
    tracing_info!(
        request.endpoint = String::from(matched_path.as_str()),
        request.method = %method,
        request.headers = ?parsed_req_headers,
        "parsed request headers",
    );
    // kv logging example - slightly different syntax - see https://docs.rs/log/latest/log/kv/
    log_info!(
        "request.endpoint" = matched_path.as_str(),
        "request.method" = method.as_str(),
        "request.headers":? = parsed_req_headers;
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

#[instrument(level = "trace", skip(body))]
async fn echo_json(
    matched_path: MatchedPath,
    method: Method,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<EchoJSONResponse> {
    let req_method = method.to_string();
    let parsed_req_headers = parse_request_headers(headers);
    // method and headers get recorded on the trace by the instrument macro; this is just an example
    // see https://docs.rs/tracing/latest/tracing/#recording-fields
    tracing_info!(
        request.endpoint = String::from(matched_path.as_str()),
        request.method = %method,
        request.headers = ?parsed_req_headers,
        "parsed request headers",
    );
    // kv logging example - slightly different syntax - see https://docs.rs/log/latest/log/kv/
    log_info!(
        "request.endpoint" = matched_path.as_str(),
        "request.method" = method.as_str(),
        "request.headers":? = parsed_req_headers;
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
