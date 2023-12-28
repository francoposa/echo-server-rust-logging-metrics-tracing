# echo-server-rust-logging-tracing-metrics

## Configuration

### OTEl Official Configuration

OpenTelemetry library configuration is done with the standardized environment variables listed here
[here](https://opentelemetry.io/docs/concepts/sdk-configuration/) and
[here] (https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/).

Of particular interest are:

* `OTEL_EXPORTER_OTLP_ENDPOINT` - this server currently only exports via gRPC.
  The RPC exporter endpoint defaults to `http://localhost:4317`.
  Endpoints can also be configured separately for metrics and (logs + traces) via
  `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` and `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`.
* `OTEL_METRIC_EXPORT_INTERVAL` - this defaults to 60000 (60 seconds), but I set it to 10000 or 15000 (10 or 15
  seconds).
  I primarily export metrics to Mimir/Prometheus/Grafana where I want to evaluate or graph the metrics rate on
  one-minute intervals.
  The rule of thumb for Prometheus-compatible tooling seems to be an
  [evaluation range >= 4x the scrape interval](https://www.robustperception.io/what-range-should-i-use-with-rate/).

### Additional Configuration

I have also added the options to enable or disable stdout/stderr logging, file logging, (logs + traces) exporting, and
metrics exporting:

* `FILE_LOGS_TRACES_EXPORTER_ENABLED`: default `false`
* `STD_STREAM_LOGS_TRACES_EXPORTER_ENABLED`: default `false`
* `OTEL_COLLECTOR_LOGS_TRACES_EXPORTER_ENABLED`: default `true`
* `OTEL_COLLECTOR_METRICS_EXPORTER_ENABLED`: default `true`

Environment variable names and defaults subject to change.

File and stdout/stderr exporters are still OTEL-structured logs and traces,
just not using the OTEL Rust exporter SDKs which are focused on exports over the wire to collectors.

## Usage

### Docker Compose

#### Echo Server

In the `development` directory, bring up the echo server with:

```shell
docker-compose up -d echo-server  # add the --build option to include any local changes
```

The Docker Compose configuration binds the container port to the host network's port 5000.
Hit either the vanilla echo endpoint at `localhost:5000` or the json echo endpoint at `localhost:5000/json`:

```shell
curl -i -X GET localhost:5000/ -d 'hello world'

curl -i -X GET --header "content-type: application/json" localhost:5000/json -d '{"hello": "world"}'
```

#### Telemetry Collectors

Only use one of the two collectors for the telemetry data, either the OTEL Collector or Grafana Agent:

```shell
docker-compose up -d otel-collector
# or
docker-compose up -d grafana-agent
```

For now, the pre-set-up configuration options are more limited for the Grafana Agent.

#### Ingesting And Visualizing Metrics:

The Docker Compose setup uses Grafana's Mimir metrics database in monolithic mode to ingest metrics,
and Grafana (the visualization application itself) to query and graph the data.

Querying may also be done via HTTP calls to Mimir's Prometheus query endpoints.

```shell
docker compose up -d mimir grafana
```

Access the Grafana UI at `localhost:3000/explore` and view the metrics with a PromQL query:

```PromQL
rate(http_server_request_duration_count[1m])
```

### Ingesting and Visualizing Traces

The easiest way to view traces is with the Jaeger all-in-one docker image.
Jaeger added support for OpenTelemetry-formatted traces in v1.35

```shell
docker run -d --name jaeger \
  -e COLLECTOR_OTLP_ENABLED=true \
  -p 16686:16686 \
  -p 4317:4317 \
  -p 4318:4318 \
  jaegertracing/all-in-one:1.35
```

Then access the Jaeger UI at http://localhost:16686.
The echo server service will appear once traces have been produced.
Make individual requests to the server or use the load gen scripts and container to create activity on the server.

Trace spans do not link together much at this point - I believe this is due to the lack of tracing support thus far in
Hyper.

## Development

Compiling requires the protobuf compiler packages, usually called `protobuf-devel` or similar in Linux repos
