# OpenTelemetry Tracing for Market Analysis Agent

## Overview

The Market Analysis Agent now includes comprehensive OpenTelemetry tracing support, enabling end-to-end visibility into market analysis workflows, request processing, and integration with other A2A agents.

## Architecture

### Tracing Components

1. **Tracing Configuration** (`tracing_config.py`)
   - Centralized OpenTelemetry setup
   - OTLP gRPC exporter for Jaeger integration
   - Console exporter for local development
   - Graceful fallback to no-op tracing

2. **Agent Integration**
   - High-level span creation for key workflows
   - Context propagation from incoming requests
   - Event and attribute tracking for business logic

3. **Context Propagation**
   - W3C Trace Context header support
   - Automatic context extraction from HTTP headers
   - Context injection for downstream calls

## Configuration

### Environment Variables

```bash
# OpenTelemetry Tracing Configuration
JAEGER_HOST=localhost
JAEGER_PORT=4317
```

### Dependencies

```toml
dependencies = [
    "opentelemetry-api>=1.20.0",
    "opentelemetry-sdk>=1.20.0",
    "opentelemetry-instrumentation-httpx>=0.40b0",
    "opentelemetry-exporter-otlp-proto-grpc>=1.20.0",
]
```

## Usage

### Basic Tracing

```python
from tracing_config import span, add_event, set_attribute

# Create a span
with span("market_analysis_agent.invoke") as span_obj:
    add_event("analysis_started")
    set_attribute("request.type", "inventory_analysis")
    # ... your code ...
```

### Context Propagation

```python
from tracing_config import extract_context_from_headers, inject_context_to_headers

# Extract context from incoming headers
trace_context = extract_context_from_headers(headers)

# Inject context into outgoing headers
outgoing_headers = inject_context_to_headers(trace_context)
```

## Trace Structure

### High-Level Spans

1. **`market_analysis_agent.executor.execute`**
   - Root span for all incoming requests
   - Extracts trace context from headers
   - Handles request routing

2. **`market_analysis_agent.invoke`**
   - Main business logic execution
   - Request parsing and analysis orchestration
   - Response formatting

3. **`market_analysis_agent.process_request`**
   - Core analysis workflow execution
   - Business policy application
   - Result generation

### Events and Attributes

- **Request Processing**: `invoke_started`, `request_parsed`, `analysis_completed`
- **Business Logic**: `inventory_demand_analysis_started`, `delegation_execution_started`
- **Integration**: `mcp_tools_discovered`, `agent_invoke_successful`
- **Error Handling**: `agent_invoke_failed`, `analysis_workflow_failed`

## Integration with Supply Chain Agent

### End-to-End Tracing

When the Supply Chain Agent calls the Market Analysis Agent:

1. **Supply Chain Agent** creates a trace with span `supply_chain_agent.get_market_analysis`
2. **Market Analysis Agent** receives the trace context via W3C headers
3. **Market Analysis Agent** creates child spans under the parent context
4. **Jaeger** displays the complete trace chain

### Example Trace Flow

```
supply_chain_agent.executor.execute
├── supply_chain_agent.invoke
│   └── supply_chain_agent.get_market_analysis
│       └── market_analysis_agent.executor.execute
│           ├── market_analysis_agent.invoke
│           └── market_analysis_agent.process_request
```

## Testing

### Test Client

The `test_client.py` includes comprehensive tracing tests:

```bash
# Run all tests including tracing
uv run test_client.py

# Test specific functionality
python -c "
import asyncio
from test_client import test_tracing_functionality
asyncio.run(test_tracing_functionality())
"
```

### Trace Context Generation

```python
from test_client import generate_trace_context, create_tracing_headers

# Generate test trace context
trace_context = generate_trace_context()

# Create headers for propagation
headers = create_tracing_headers(trace_context)
```

## Troubleshooting

### Common Issues

1. **Jaeger Connection Failed**
   - Check `JAEGER_HOST` and `JAEGER_PORT` environment variables
   - Verify Jaeger is running and accessible
   - Check firewall/network connectivity

2. **No Spans Appearing**
   - Verify tracing initialization in logs
   - Check console exporter output
   - Ensure no exceptions during span creation

3. **Context Propagation Issues**
   - Verify W3C Trace Context headers are present
   - Check propagator configuration
   - Ensure consistent header format

### Debug Mode

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Console Exporter

For local development without Jaeger:

```python
initialize_tracing(
    service_name="market-analysis-agent",
    enable_console_exporter=True  # No Jaeger host
)
```

## Production Deployment

### Recommended Configuration

```python
initialize_tracing(
    service_name="market-analysis-agent",
    jaeger_host="jaeger.internal.company.com",
    jaeger_port=4317,
    enable_console_exporter=False  # Disable in production
)
```

### Security Considerations

- Use secure connections to Jaeger in production
- Implement proper authentication for tracing endpoints
- Consider sampling for high-traffic environments

### Performance Impact

- Tracing adds minimal overhead (<1ms per span)
- Batch processing reduces network calls
- No-op mode available for performance-critical scenarios

## Monitoring and Alerting

### Key Metrics

- **Request Latency**: Track span duration for performance monitoring
- **Error Rates**: Monitor spans with error status
- **Trace Completeness**: Ensure end-to-end trace coverage

### Alerts

- High error rates in market analysis workflows
- Long response times for analysis requests
- Failed context propagation between agents

## Future Enhancements

### Planned Features

1. **Custom Metrics**: Business-specific metrics (analysis accuracy, recommendation quality)
2. **Sampling Strategies**: Intelligent sampling for high-volume requests
3. **Trace Correlation**: Link traces with business transactions
4. **Performance Profiling**: Detailed performance analysis within spans

### Integration Opportunities

- **APM Tools**: Integration with New Relic, Datadog, etc.
- **Log Correlation**: Link traces with structured logs
- **Business Intelligence**: Trace-based business metrics and analytics
