# OpenTelemetry Tracing for Supply Chain Agent

This document describes the OpenTelemetry tracing implementation in the Supply Chain Optimizer Agent.

## Overview

The Supply Chain Agent now includes comprehensive OpenTelemetry tracing support that provides:

- **End-to-end visibility** into supply chain optimization requests
- **Performance insights** for market analysis calls
- **Debugging capabilities** for complex business logic flows
- **Compliance tracking** for financial and policy decisions
- **Integration monitoring** between different agent services

## Architecture

### Tracing Flow

```
Test Client → Supply Chain Agent → Market Analysis Agent
     ↓              ↓                    ↓
  Creates      Extracts context      Receives context
  trace       Creates spans         Creates child spans
  context     Propagates headers    Links to parent trace
```

### Span Structure

- **Root Span**: Test client request
- **Child Spans**: 
  - Supply chain optimization
  - Business policy validation
  - Market analysis call
  - Response processing

## Configuration

### Environment Variables

Create a `.env` file or set these environment variables:

```bash
# Agent URLs
SUPPLY_CHAIN_AGENT_URL=http://localhost:9999/
MARKET_ANALYSIS_AGENT_URL=http://localhost:9998/

# OpenTelemetry Tracing Configuration
JAEGER_HOST=localhost
JAEGER_PORT=4317

# Environment
ENVIRONMENT=development
```

### Tracing Backends

#### Console Exporter (Default)
- Always enabled for development
- Outputs spans to console/logs
- Useful for debugging and development

#### Jaeger Exporter
- Set `JAEGER_HOST` to enable
- Default port: 4317
- Provides web UI for trace visualization

## Usage

### Starting the Agent with Tracing

```bash
# Start with console tracing only
python -m supply_chain_agent

# Start with Jaeger tracing
JAEGER_HOST=localhost python -m supply_chain_agent
```

### Testing Tracing

Run the test client to see tracing in action:

```bash
cd supply-chain-agent
python test_client.py
```

The test client will:
1. Generate unique trace contexts for each test
2. Display trace IDs and span IDs
3. Show how context propagates through the system

## Tracing Features

### Context Propagation

The agent automatically:
- Extracts trace context from incoming HTTP headers
- Creates child spans for business operations
- Propagates context to downstream services (market analysis agent)
- Links all spans in a single trace

### Business Logic Tracing

#### Policy Validation
- Spans for each policy check
- Attributes for validation results
- Events for warnings and violations

#### Supply Chain Analysis
- Spans for request analysis
- Attributes for optimization focus areas
- Events for recommendation generation

#### Market Analysis Integration
- Spans for client creation
- Spans for API calls
- Attributes for response processing

### Span Attributes

Key attributes are automatically added to spans:

```python
# Request attributes
"request.text": "optimize laptop supply chain"
"request.has_content": True

# Business logic attributes
"analysis.focus_area": "laptop_inventory"
"analysis.optimization_goal": "cost_optimization"

# Policy validation attributes
"validation.order_value": 75000
"validation.vendor": "Dell"
"validation.is_valid": True
```

### Span Events

Important business events are recorded:

```python
# Policy events
"policy_validation_started"
"policy_violation"
"policy_warning"

# Business logic events
"focus_area_determined"
"recommendations_generated"
"market_analysis_requested"
```

## Testing

### Manual Testing

1. **Start the agent**:
   ```bash
   python -m supply_chain_agent
   ```

2. **Run test client**:
   ```bash
   python test_client.py
   ```

3. **Check console output** for span information

### Jaeger Testing

1. **Start Jaeger** (using Docker):
   ```bash
   docker run -d --name jaeger \
     -e COLLECTOR_OTLP_ENABLED=true \
     -p 16686:16686 \
     -p 6831:6831 \
     jaegertracing/all-in-one:latest
   ```

2. **Set environment**:
   ```bash
   export JAEGER_HOST=localhost
   export JAEGER_PORT=4317
   ```

3. **Start agent and run tests**

4. **View traces** at http://localhost:16686

## Troubleshooting

### Common Issues

#### Tracing Not Working
- Check that OpenTelemetry dependencies are installed
- Verify environment variables are set correctly
- Check console for initialization messages

#### Spans Not Appearing
- Ensure tracing is initialized before agent creation
- Check that spans are created within proper context
- Verify console exporter is enabled

#### Context Not Propagating
- Check HTTP headers are properly formatted
- Verify trace context extraction logic
- Ensure child spans are created with parent context

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Console Output

When console exporter is enabled, you'll see output like:

```
🔗 Initializing OpenTelemetry tracing...
🔗 Tracing configured with console exporter only
🚀 Starting Supply Chain Agent on port 9999
```

## Performance Considerations

### Span Limits
- Attribute values are truncated to 100 characters
- Large objects are converted to strings
- Events include only essential information

### Sampling
- All spans are sampled by default
- Can be configured for production environments
- Consider sampling strategies for high-traffic scenarios

### Storage
- Console exporter: No persistent storage
- Jaeger exporter: Configurable retention policies
- Consider data volume for production deployments

## Production Deployment

### Recommended Configuration

```bash
# Production environment
ENVIRONMENT=production
JAEGER_HOST=jaeger.internal.company.com
JAEGER_PORT=4317
ENABLE_CONSOLE_EXPORTER=false

# Optional: Custom sampling
OTEL_TRACES_SAMPLER=parentbased_traceidratio
OTEL_TRACES_SAMPLER_ARG=0.1
```

### Monitoring

- Monitor Jaeger storage usage
- Set up alerts for trace failures
- Track span duration metrics
- Monitor context propagation success rates

## Integration with Other Services

### Market Analysis Agent
- Context automatically propagated via HTTP headers
- Child spans created for each API call
- Error handling with span status updates

### Future Integrations
- Database operations
- External API calls
- Message queue operations
- File system operations

## Contributing

### Adding New Spans

1. Import tracing utilities:
   ```python
   from .tracing_config import span, add_event, set_attribute
   ```

2. Create spans for operations:
   ```python
   with span("operation_name") as span_obj:
       # Your operation logic
       add_event("operation_started")
       set_attribute("operation.type", "example")
   ```

3. Add meaningful attributes and events

### Best Practices

- Use descriptive span names
- Include relevant business attributes
- Record important events
- Handle errors with proper span status
- Keep attribute values concise

## References

- [OpenTelemetry Python Documentation](https://opentelemetry.io/docs/languages/python/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [Jaeger Documentation](https://www.jaegertracing.io/docs/)
- [A2A Framework Documentation](https://github.com/your-org/a2a-python)
