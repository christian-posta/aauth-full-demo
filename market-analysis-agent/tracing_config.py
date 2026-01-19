"""
OpenTelemetry tracing configuration for Market Analysis Agent.
"""

import os
import logging
from contextlib import contextmanager
from typing import Dict, Any, Optional

# OpenTelemetry imports
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.trace.sampling import Sampler, SamplingResult, Decision
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    from opentelemetry.trace import Status, StatusCode
    from opentelemetry.sdk.trace import ReadableSpan
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
    OTEL_AVAILABLE = True
except ImportError as e:
    logging.warning(f"OpenTelemetry not available: {e}")
    OTEL_AVAILABLE = False

class NoisySpanFilter(SpanExporter):
    """Custom span exporter that filters out noisy A2A framework spans."""
    
    def __init__(self, base_exporter: SpanExporter):
        self.base_exporter = base_exporter
        self.noisy_patterns = [
            "a2a.server.events.event_queue.EventQueue.dequeue_event",
            "a2a.server.events.event_queue.EventQueue.enqueue_event",
            "a2a.server.events.in_memory_queue_manager.InMemoryQueueManager",
            "a2a.server.request_handlers.default_request_handler.DefaultRequestHandler",
        ]
    
    def export(self, spans: list[ReadableSpan]) -> SpanExportResult:
        """Export spans, filtering out noisy ones."""
        filtered_spans = []
        for span in spans:
            # Keep spans that don't match noisy patterns
            if not any(pattern in span.name for pattern in self.noisy_patterns):
                filtered_spans.append(span)
        
        # Only export if we have spans to export
        if filtered_spans:
            return self.base_exporter.export(filtered_spans)
        else:
            # Return success for empty export
            return SpanExportResult.SUCCESS
    
    def shutdown(self) -> None:
        """Shutdown the base exporter."""
        self.base_exporter.shutdown()

class TracingConfig:
    """OpenTelemetry tracing configuration for Market Analysis Agent."""
    
    def __init__(self):
        self._initialized = False
        self.tracer_provider = None
        self.tracer = None
        self.propagator: Optional[TraceContextTextMapPropagator] = None
        
    def initialize(self, service_name: str = "market-analysis-agent", 
                   jaeger_host: Optional[str] = None, 
                   jaeger_port: int = 4317,
                   enable_console_exporter: bool = None):
        """Initialize OpenTelemetry tracing."""
        if not OTEL_AVAILABLE:
            logging.warning("OpenTelemetry not available, using no-op tracing")
            return
        
        # Check environment variable for console exporter if not explicitly set
        if enable_console_exporter is None:
            enable_console_exporter = os.getenv("ENABLE_CONSOLE_EXPORTER", "true").lower() == "true"
        
        # Log the console exporter status
        if enable_console_exporter:
            logging.info("Console trace span logging: ENABLED")
        else:
            logging.info("Console trace span logging: DISABLED")
            
        try:
            # Create resource with service name
            resource = Resource.create({
                "service.name": service_name,
                "service.version": "1.0.0",
                "deployment.environment": os.getenv("ENVIRONMENT", "development")
            })
            
            # Create tracer provider with simple sampling (no custom sampler for now)
            self.tracer_provider = TracerProvider(
                resource=resource
            )
            
            # Add console exporter if enabled
            if enable_console_exporter:
                console_exporter = ConsoleSpanExporter()
                # Wrap with filter to remove noisy spans
                filtered_console_exporter = NoisySpanFilter(console_exporter)
                self.tracer_provider.add_span_processor(
                    BatchSpanProcessor(filtered_console_exporter)
                )
            
            # Add OTLP exporter if Jaeger host is provided
            if jaeger_host:
                try:
                    otlp_exporter = OTLPSpanExporter(
                        endpoint=f"{jaeger_host}:{jaeger_port}",
                        insecure=True,
                    )
                    # Wrap with filter to remove noisy spans
                    filtered_otlp_exporter = NoisySpanFilter(otlp_exporter)
                    self.tracer_provider.add_span_processor(
                        BatchSpanProcessor(filtered_otlp_exporter)
                    )
                    logging.info(f"OTLP exporter configured for {jaeger_host}:{jaeger_port}")
                except Exception as e:
                    logging.warning(f"Failed to configure OTLP exporter: {e}")
            
            # Set as global tracer provider
            trace.set_tracer_provider(self.tracer_provider)
            
            # Get tracer
            self.tracer = trace.get_tracer(__name__)
            
            # Set up propagator
            self.propagator = TraceContextTextMapPropagator()
            
            # Instrument HTTPX client
            try:
                HTTPXClientInstrumentor().instrument()
                logging.info("HTTPX client instrumentation enabled")
            except Exception as e:
                logging.warning(f"Failed to instrument HTTPX client: {e}")
            
            self._initialized = True
            logging.info(f"Tracing initialized for service: {service_name}")
            
        except Exception as e:
            logging.error(f"Failed to initialize OpenTelemetry: {e}")
            # Fallback to console-only tracing
            self._initialize_fallback(service_name)
    
    def _initialize_fallback(self, service_name: str):
        """Initialize fallback tracing with console exporter only."""
        try:
            resource = Resource.create({"service.name": service_name})
            self.tracer_provider = TracerProvider(resource=resource)
            
            console_exporter = ConsoleSpanExporter()
            # Wrap with filter to remove noisy spans
            filtered_console_exporter = NoisySpanFilter(console_exporter)
            self.tracer_provider.add_span_processor(
                BatchSpanProcessor(filtered_console_exporter)
            )
            
            trace.set_tracer_provider(self.tracer_provider)
            self.tracer = trace.get_tracer(__name__)
            self._initialized = True
            
            logging.warning("Tracing initialized in fallback mode (console only)")
            
        except Exception as e:
            logging.error(f"Failed to initialize fallback tracing: {e}")
            # Final fallback: create a no-op tracer that does nothing
            self._initialize_noop_tracer(service_name)
    
    def _initialize_noop_tracer(self, service_name: str):
        """Initialize a no-op tracer that does nothing but prevents crashes."""
        try:
            # Create a minimal tracer provider that does nothing
            self.tracer_provider = TracerProvider()
            trace.set_tracer_provider(self.tracer_provider)
            self.tracer = trace.get_tracer(__name__)
            self._initialized = True
            
            logging.warning("Tracing initialized in no-op mode")
            
        except Exception as e:
            logging.error(f"Failed to initialize no-op tracing: {e}")
            # Ultimate fallback: use dummy classes
            self.tracer_provider = DummyTracerProvider()
            self.tracer = DummyTracer()
            self._initialized = False
    
    def get_tracer(self):
        """Get the tracer instance."""
        if not self._initialized:
            self.initialize()
        return self.tracer
    
    @contextmanager
    def span(self, name: str, attributes: Optional[Dict[str, Any]] = None, 
             parent_context: Optional[trace.SpanContext] = None):
        """Create a span context manager."""
        if not self._initialized:
            self.initialize()
        
        if self.tracer is None:
            # No-op mode
            yield DummySpan()
            return
        
        tracer = self.get_tracer()
        
        # Handle parent context if provided
        if parent_context:
            try:
                # Create span with parent context
                with tracer.start_as_current_span(name, context=parent_context) as span:
                    if attributes:
                        for key, value in attributes.items():
                            span.set_attribute(key, value)
                    try:
                        yield span
                    except Exception as e:
                        span.set_status(Status(StatusCode.ERROR, str(e)))
                        span.record_exception(e)
                        raise
            except Exception as e:
                logging.warning(f"Failed to create span with parent context: {e}")
                # Fallback to span without parent context
                with tracer.start_as_current_span(name) as span:
                    if attributes:
                        for key, value in attributes.items():
                            span.set_attribute(key, value)
                    try:
                        yield span
                    except Exception as e:
                        span.set_status(Status(StatusCode.ERROR, str(e)))
                        span.record_exception(e)
                        raise
        else:
            # Create span without parent context
            with tracer.start_as_current_span(name) as span:
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)
                try:
                    yield span
                except Exception as e:
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise
    
    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """Add an event to the current span."""
        if not self._initialized:
            return
        
        current_span = trace.get_current_span()
        if current_span and current_span.is_recording():
            current_span.add_event(name, attributes or {})
    
    def set_attribute(self, key: str, value: Any):
        """Set an attribute on the current span."""
        if not self._initialized:
            return
        
        current_span = trace.get_current_span()
        if current_span and current_span.is_recording():
            current_span.set_attribute(key, value)
    
    def extract_context_from_headers(self, headers: Dict[str, str]) -> Optional[trace.SpanContext]:
        """Extract trace context from headers."""
        if not self._initialized or not self.propagator:
            return None
        
        try:
            # Use the correct OpenTelemetry API - extract from carrier with proper context
            from opentelemetry.context import Context
            context = self.propagator.extract(
                carrier=headers, 
                context=Context()
            )
            return context
        except Exception as e:
            logging.warning(f"Failed to extract trace context: {e}")
            return None
    
    def inject_context_to_headers(self, context: trace.SpanContext) -> Dict[str, str]:
        """Inject trace context into headers."""
        if not self._initialized or not self.propagator:
            return {}
        
        try:
            headers = {}
            self.propagator.inject(context, carrier=headers, setter=dict.__setitem__)
            return headers
        except Exception as e:
            logging.warning(f"Failed to inject trace context: {e}")
            return {}

# Global instance
_tracing_config = TracingConfig()

def initialize_tracing(service_name: str = "market-analysis-agent",
                      jaeger_host: Optional[str] = None,
                      jaeger_port: int = 4317,
                      enable_console_exporter: bool = None):
    """Initialize tracing configuration."""
    _tracing_config.initialize(service_name, jaeger_host, jaeger_port, enable_console_exporter)

def span(name: str, attributes: Optional[Dict[str, Any]] = None, parent_context: Optional[trace.SpanContext] = None):
    """Create a span context manager."""
    return _tracing_config.span(name, attributes, parent_context)

def add_event(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Add an event to the current span."""
    _tracing_config.add_event(name, attributes)

def set_attribute(key: str, value: Any):
    """Set an attribute on the current span."""
    _tracing_config.set_attribute(key, value)

def extract_context_from_headers(headers: Dict[str, str]) -> Optional[trace.SpanContext]:
    """Extract trace context from headers."""
    return _tracing_config.extract_context_from_headers(headers)

def inject_context_to_headers(context: trace.SpanContext) -> Dict[str, str]:
    """Inject trace context into headers."""
    return _tracing_config.inject_context_to_headers(context)
