use std::collections::HashMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Json, MatchedPath};
use axum::http::{HeaderMap, Method};
use axum::routing::{get, post, put, Router};
use envy;
use log::info as log_info;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::trace::TracerProvider;
use opentelemetry_appender_tracing;
use opentelemetry_instrumentation_tower;
use opentelemetry_otlp;
use opentelemetry_sdk;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::signal;
use tower_http::classify::StatusInRangeAsFailures;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info as tracing_info, instrument};
use tracing_subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

const SERVICE_NAME: &str = "echo-server-rust";

#[derive(Deserialize)]
struct Config {
    #[serde(default = "server_addr")]
    server_addr: String,

    #[serde(default = "base_url_path_v0")]
    base_url_path: String,

    #[serde(default = "std_stream_exporter_enabled")]
    std_stream_logs_exporter_enabled: bool,

    #[serde(default = "std_stream_exporter_enabled")]
    std_stream_metrics_exporter_enabled: bool,

    #[serde(default = "std_stream_exporter_enabled")]
    std_stream_traces_exporter_enabled: bool,

    #[serde(default = "otel_collector_exporter_enabled")]
    otel_collector_logs_exporter_enabled: bool,

    #[serde(default = "otel_collector_exporter_enabled")]
    otel_collector_metrics_exporter_enabled: bool,

    #[serde(default = "otel_collector_exporter_enabled")]
    otel_collector_traces_exporter_enabled: bool,
}

fn server_addr() -> String {
    String::from("0.0.0.0:8080")
}

fn base_url_path_v0() -> String {
    String::from("/api/v0")
}

fn enabled() -> bool {
    true
}

fn std_stream_exporter_enabled() -> bool {
    false
}

fn otel_collector_exporter_enabled() -> bool {
    true
}

fn init_otel_resource() -> opentelemetry_sdk::Resource {
    let otlp_resource_detected = opentelemetry_sdk::Resource::builder()
        .with_detector(Box::new(
            opentelemetry_sdk::resource::SdkProvidedResourceDetector,
        ))
        .with_detector(Box::new(
            opentelemetry_sdk::resource::EnvResourceDetector::new(),
        ))
        .with_detector(Box::new(
            opentelemetry_sdk::resource::TelemetryResourceDetector,
        ))
        .with_service_name(SERVICE_NAME);

    otlp_resource_detected.build()
}

// ************************************ METRICS ************************************
fn init_metrics(
    config: &Config,
    resource: opentelemetry_sdk::Resource,
) -> opentelemetry_sdk::metrics::SdkMeterProvider {
    let mut meter_provider_builder = opentelemetry_sdk::metrics::SdkMeterProvider::builder();

    if config.std_stream_metrics_exporter_enabled {
        let std_stream_exporter = opentelemetry_stdout::MetricExporter::default();
        let std_stream_reader =
            opentelemetry_sdk::metrics::PeriodicReader::builder(std_stream_exporter)
                .with_interval(Duration::from_secs(10))
                .build();

        meter_provider_builder = meter_provider_builder.with_reader(std_stream_reader)
    }
    if config.otel_collector_metrics_exporter_enabled {
        let otlp_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .build()
            .unwrap();

        let otlp_reader = opentelemetry_sdk::metrics::PeriodicReader::builder(otlp_exporter)
            .with_interval(Duration::from_secs(10))
            .build();

        meter_provider_builder = meter_provider_builder.with_reader(otlp_reader)
    }

    let meter_provider = meter_provider_builder.with_resource(resource).build();
    meter_provider
}

// ************************************ LOGS ************************************
fn init_logs(
    config: &Config,
    resource: opentelemetry_sdk::Resource,
) -> opentelemetry_sdk::logs::SdkLoggerProvider {
    let mut log_provider_builder = opentelemetry_sdk::logs::SdkLoggerProvider::builder();

    if config.std_stream_logs_exporter_enabled {
        let stdout_log_exporter = opentelemetry_stdout::LogExporter::default();

        log_provider_builder = log_provider_builder.with_simple_exporter(stdout_log_exporter);
    }

    if config.otel_collector_logs_exporter_enabled {
        let otlp_log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .build()
            .unwrap();

        log_provider_builder = log_provider_builder.with_batch_exporter(otlp_log_exporter);
    }

    let log_provider = log_provider_builder.with_resource(resource).build();
    log_provider
}

// ************************************ TRACES ************************************
fn init_traces(
    config: &Config,
    resource: opentelemetry_sdk::Resource,
) -> opentelemetry_sdk::trace::SdkTracerProvider {
    // init otel tracing propogator; see more about opentelemetry propagators here:
    // https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/context/api-propagators.md
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let mut tracer_provider_builder = opentelemetry_sdk::trace::SdkTracerProvider::builder();

    if config.std_stream_traces_exporter_enabled {
        let std_stream_trace_exporter = opentelemetry_stdout::SpanExporter::default();

        tracer_provider_builder =
            tracer_provider_builder.with_simple_exporter(std_stream_trace_exporter);
    }

    if config.otel_collector_traces_exporter_enabled {
        let otlp_trace_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .build()
            .unwrap();

        // using the batch processor builder and enabling it with with_span_processor
        // to configure exporter settings like batch size, timeout, etc.
        // which cannot be set when using with_batch_exporter.
        let batch_processor =
            opentelemetry_sdk::trace::BatchSpanProcessor::builder(otlp_trace_exporter)
                .with_batch_config(
                    opentelemetry_sdk::trace::BatchConfigBuilder::default()
                        .with_scheduled_delay(Duration::from_secs(10))
                        .build(),
                )
                .build();

        tracer_provider_builder = tracer_provider_builder.with_span_processor(batch_processor);
    }

    let tracer_provider = tracer_provider_builder.with_resource(resource).build();

    tracer_provider
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = envy::from_env::<Config>().unwrap();

    let otel_resource = init_otel_resource();

    let meter_provider = init_metrics(&config, otel_resource.clone());
    opentelemetry::global::set_meter_provider(meter_provider.clone());
    let meter = meter_provider.meter(SERVICE_NAME);

    // this layer a tower service middleware layer, not a tracing subscriber layer
    let otel_metrics_service_layer =
        opentelemetry_instrumentation_tower::HTTPMetricsLayerBuilder::builder()
            .with_meter(meter)
            .build()
            .unwrap();

    // bring logs and traces together with the tracing bridge
    let log_provider = init_logs(&config, otel_resource.clone());
    let otel_log_subscriber_layer =
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&log_provider)
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO);

    let tracer_provider = init_traces(&config, otel_resource.clone());
    let tracer = tracer_provider.tracer(SERVICE_NAME);
    let otel_trace_subscriber_layer = tracing_opentelemetry::OpenTelemetryLayer::new(tracer);
    let otel_tracing_subscriber = tracing_subscriber::Registry::default()
        .with(otel_log_subscriber_layer)
        .with(otel_trace_subscriber_layer);

    opentelemetry::global::set_tracer_provider(tracer_provider);
    tracing::subscriber::set_global_default(otel_tracing_subscriber).unwrap();

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

    Ok(())
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
