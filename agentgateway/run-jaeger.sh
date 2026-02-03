docker run -it \
  --name jaeger-tracing \
  --rm \
  -p 127.0.0.1:16686:16686 \
  -p 127.0.0.1:14268:14268 \
  -p 127.0.0.1:4317:4317 \
  -e COLLECTOR_OTLP_ENABLED=true \
  jaegertracing/all-in-one:latest
