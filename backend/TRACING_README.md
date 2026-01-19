# OpenTelemetry Tracing in Supply Chain Backend

This document describes the OpenTelemetry tracing implementation in the Supply Chain Backend API.

## Overview

The backend now includes comprehensive OpenTelemetry tracing that provides:
- **Request tracing**: Every API endpoint creates spans for request processing
- **Service tracing**: All service methods are instrumented with spans and events
- **A2A agent tracing**: Complete tracing of A2A agent communication
- **Context propagation**: Trace context is extracted from incoming headers and propagated to downstream services
- **Console and OTLP export**: Spans are exported to console and optionally to Jaeger/OTLP collector

## Architecture

```
Client Request → FastAPI → API Endpoint → Service Layer → A2A Agent
     ↓              ↓           ↓            ↓            ↓
  Headers      Middleware    Spans      Spans      Tracing Interceptor
  (traceparent)  (CORS)     (API)     (Service)   (HTTP Headers)
```

## Key Components

### 1. Tracing Configuration (`app/tracing_config.py`)
- **TracingConfig**: Main configuration class for OpenTelemetry
- **NoisySpanFilter**: Filters out framework noise (CORS, uvicorn, etc.)
- **Fallback handling**: Graceful degradation if tracing fails to initialize

### 2. Tracing Interceptor (`app/services/tracing_interceptor.py`)
- **TracingInterceptor**: A2A client interceptor that injects trace context
- **Header injection**: Automatically adds trace headers to A2A agent requests
- **Context propagation**: Ensures trace continuity across service boundaries

### 3. Service Instrumentation
- **OptimizationService**: Fully instrumented with spans and events
- **A2AService**: Complete tracing of A2A agent communication
- **API endpoints**: All endpoints create spans and extract trace context

## Configuration

### Environment Variables

```bash
# Optional: Jaeger/OTLP collector endpoint
JAEGER_HOST=localhost
JAEGER_PORT=4317

# Optional: Environment name
ENVIRONMENT=development
```

### Dependencies

The following OpenTelemetry packages are required:
```toml
opentelemetry-api>=1.20.0
opentelemetry-sdk>=1.20.0
opentelemetry-instrumentation-httpx>=0.40b0
opentelemetry-instrumentation-fastapi>=0.40b0
opentelemetry-exporter-otlp-proto-grpc>=1.20.0
```

## Usage

### Starting the Backend with Tracing

Tracing is automatically initialized when the FastAPI app starts:

```python
# In app/main.py
from app.tracing_config import initialize_tracing

# Initialize tracing before creating the FastAPI app
initialize_tracing(
    service_name="supply-chain-backend",
    jaeger_host=os.getenv("JAEGER_HOST"),
    jaeger_port=int(os.getenv("JAEGER_PORT", "4317")),
    enable_console_exporter=True
)
```

### Using Tracing in Services

```python
from app.tracing_config import span, add_event, set_attribute

class MyService:
    def my_method(self):
        with span("my_service.my_method", {
            "param1": "value1",
            "param2": "value2"
        }) as span_obj:
            
            # Add events to the span
            add_event("method_started", {"timestamp": "now"})
            
            # Set attributes
            set_attribute("service.name", "my_service")
            
            # Your business logic here
            result = self.do_work()
            
            # Add completion event
            add_event("method_completed", {"result": str(result)})
            
            return result
```

### Trace Context Propagation

The system automatically handles trace context propagation:

1. **Incoming requests**: Trace context is extracted from `traceparent` and `tracestate` headers
2. **Service calls**: Context is automatically propagated to child spans
3. **A2A calls**: Trace context is injected into HTTP headers sent to A2A agents

```python
# In API endpoints
async def my_endpoint(request: Request):
    # Extract trace context from headers
    headers = dict(request.headers)
    trace_context = extract_context_from_headers(headers)
    
    # Pass to service with context
    result = await my_service.do_work(trace_context)
```

## Testing

### Running Tracing Tests

```bash
cd backend
python test_tracing.py
```

This will test:
- Basic tracing functionality
- Service tracing
- A2A service tracing
- Span creation and event handling

### Manual Testing

1. **Start the backend**:
   ```bash
   cd backend
   python -m app.main
   ```

2. **Send a request with trace headers**:
   ```bash
   curl -H "traceparent: 00-1234567890abcdef-1234567890abcdef-01" \
        -H "tracestate: test=value" \
        http://localhost:8000/optimization/start
   ```

3. **Check console output** for span information

## Span Structure

### API Request Spans
```
optimization_api.start_optimization
├── optimization_api.run_optimization_workflow
    ├── a2a_service.optimize_supply_chain
        ├── a2a_service.create_client
        └── a2a_service.create_optimization_message
```

### Service Method Spans
```
optimization_service.create_request
optimization_service.update_progress
optimization_service.complete_optimization
optimization_service.generate_results
```

### A2A Communication Spans
```
a2a_service.optimize_supply_chain
├── a2a_service.create_client
├── a2a_service.create_optimization_message
└── a2a_client.send_message (via interceptor)
```

## Monitoring and Debugging

### Console Output
With `enable_console_exporter=True`, spans are printed to console:
```
{
  "name": "optimization_api.start_optimization",
  "context": {...},
  "attributes": {...},
  "events": [...]
}
```

### Jaeger Integration
If `JAEGER_HOST` is set, spans are sent to Jaeger:
1. Start Jaeger: `docker run -p 16686:16686 jaegertracing/all-in-one`
2. Set environment: `export JAEGER_HOST=localhost`
3. View traces at: `http://localhost:16686`

### Common Issues

1. **Tracing not working**: Check console for initialization errors
2. **Missing spans**: Verify `enable_console_exporter=True`
3. **Context propagation issues**: Check header extraction in API endpoints
4. **A2A tracing not working**: Verify interceptor is properly configured

## Best Practices

1. **Use descriptive span names**: `service.method_name` format
2. **Add meaningful events**: Log important state changes
3. **Set relevant attributes**: Include business context
4. **Handle errors gracefully**: Use try-catch with span error recording
5. **Avoid over-instrumentation**: Focus on business logic, not framework details

## Future Enhancements

- **Metrics integration**: Add Prometheus metrics alongside traces
- **Log correlation**: Link logs with trace IDs
- **Sampling strategies**: Implement intelligent sampling for high-volume scenarios
- **Custom exporters**: Support for additional observability backends
- **Performance profiling**: Add flame graph generation

