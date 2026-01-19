#!/usr/bin/env python3
"""OpenTelemetry tracing configuration for the Supply Chain Optimizer Agent."""

import os
import logging
from typing import Optional, Dict, Any
from contextlib import contextmanager

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    """Configuration and utilities for OpenTelemetry tracing."""
    
    def __init__(self):
        self.tracer_provider: Optional[TracerProvider] = None
        self.tracer: Optional[trace.Tracer] = None
        self.propagator = TraceContextTextMapPropagator()
        self._initialized = False
    
    def initialize(self, service_name: str = "supply-chain-agent", 
                  jaeger_host: Optional[str] = None, 
                  jaeger_port: int = 4317,
                  enable_console_exporter: bool = None):
        """Initialize the tracing system."""
        if self._initialized:
            return
        
        # Check environment variable for console exporter if not explicitly set
        if enable_console_exporter is None:
            enable_console_exporter = os.getenv("ENABLE_CONSOLE_EXPORTER", "true").lower() == "true"
        
        # Log the console exporter status
        if enable_console_exporter:
            logger.info("Console trace span logging: ENABLED")
        else:
            logger.info("Console trace span logging: DISABLED")
        
        try:
            # Create resource
            resource = Resource.create({
                "service.name": service_name,
                "service.version": "1.0.0",
                "deployment.environment": os.getenv("ENVIRONMENT", "development")
            })
            
            # Create tracer provider with simple sampling (no custom sampler for now)
            self.tracer_provider = TracerProvider(
                resource=resource
            )
            
            # Add span processors
            if enable_console_exporter:
                console_exporter = ConsoleSpanExporter()
                # Wrap with filter to remove noisy spans
                filtered_console_exporter = NoisySpanFilter(console_exporter)
                self.tracer_provider.add_span_processor(
                    BatchSpanProcessor(filtered_console_exporter)
                )
            
            # Add OTLP exporter if configured
            if jaeger_host:
                otlp_exporter = OTLPSpanExporter(
                    endpoint=f"{jaeger_host}:{jaeger_port}",
                    insecure=True,  # Disable SSL for local development
                )
                # Wrap with filter to remove noisy spans
                filtered_otlp_exporter = NoisySpanFilter(otlp_exporter)
                self.tracer_provider.add_span_processor(
                    BatchSpanProcessor(filtered_otlp_exporter)
                )
            
            # Set the global tracer provider
            trace.set_tracer_provider(self.tracer_provider)
            
            # Get tracer
            self.tracer = trace.get_tracer(__name__)
            
            # Instrument HTTPX client
            HTTPXClientInstrumentor().instrument()
            
            self._initialized = True
            logger.info(f"Tracing initialized for service: {service_name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize tracing: {e}")
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
            
            logger.warning("Tracing initialized in fallback mode (console only)")
            
        except Exception as e:
            logger.error(f"Failed to initialize fallback tracing: {e}")
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
            
            logger.warning("Tracing initialized in no-op mode (tracing disabled)")
            
        except Exception as e:
            logger.error(f"Failed to initialize no-op tracing: {e}")
            # Last resort: set initialized to True but tracer to None
            # This prevents crashes but disables all tracing functionality
            self._initialized = True
            self.tracer = None
            logger.critical("Tracing completely disabled - agent will continue without tracing")
    
    def get_tracer(self) -> trace.Tracer:
        """Get the configured tracer."""
        if not self._initialized:
            self.initialize()
        
        # If tracer is None (no-op mode), return a dummy tracer
        if self.tracer is None:
            # Return a no-op tracer that does nothing
            return trace.get_tracer(__name__)
        
        return self.tracer
    
    def extract_context_from_headers(self, headers: Dict[str, str]) -> Optional[trace.SpanContext]:
        """Extract trace context from HTTP headers."""
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
            logger.warning(f"Failed to extract trace context from headers: {e}")
            return None
    
    def inject_context_to_headers(self, context: trace.SpanContext) -> Dict[str, str]:
        """Inject trace context into HTTP headers."""
        if not self._initialized or not self.propagator:
            return {}
        
        try:
            headers = {}
            self.propagator.inject(context, carrier=headers, setter=dict.__setitem__)
            return headers
        except Exception as e:
            logger.warning(f"Failed to inject trace context to headers: {e}")
            return {}
    
    @contextmanager
    def span(self, name: str, attributes: Optional[Dict[str, Any]] = None, 
             parent_context: Optional[trace.SpanContext] = None):
        """Context manager for creating spans."""
        if not self._initialized:
            self.initialize()
        
        # If tracer is None (no-op mode), create a dummy context manager
        if self.tracer is None:
            # Return a dummy context manager that does nothing
            class DummySpan:
                def __enter__(self):
                    return self
                def __exit__(self, exc_type, exc_val, exc_tb):
                    pass
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
    
    def create_span(self, name: str, attributes: Optional[Dict[str, Any]] = None,
                    parent_context: Optional[trace.SpanContext] = None) -> trace.Span:
        """Create a new span."""
        if not self._initialized:
            self.initialize()
        
        # If tracer is None (no-op mode), return a dummy span
        if self.tracer is None:
            # Return a dummy span that does nothing
            class DummySpan:
                def __enter__(self):
                    return self
                def __exit__(self, exc_type, exc_val, exc_tb):
                    pass
                def set_attribute(self, key, value):
                    pass
                def add_event(self, name, attributes=None):
                    pass
                def set_status(self, status):
                    pass
                def record_exception(self, exception):
                    pass
                def get_span_context(self):
                    # Return a dummy context to avoid errors
                    return None
            return DummySpan()
        
        tracer = self.get_tracer()
        
        # Simplified span creation to avoid context issues
        try:
            span = tracer.start_span(name)
            
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, value)
            
            return span
        except Exception as e:
            logger.warning(f"Failed to create span '{name}': {e}")
            # Return a dummy span as fallback
            class DummySpan:
                def __enter__(self):
                    return self
                def __exit__(self, exc_type, exc_val, exc_tb):
                    pass
                def set_attribute(self, key, value):
                    pass
                def add_event(self, name, attributes=None):
                    pass
                def set_status(self, status):
                    pass
                def record_exception(self, exception):
                    pass
                def get_span_context(self):
                    return None
            return DummySpan()
    
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
    
    def shutdown(self):
        """Shutdown the tracing system."""
        if self.tracer_provider:
            self.tracer_provider.shutdown()
            self._initialized = False
            logger.info("Tracing system shutdown")


# Global tracing configuration instance
tracing_config = TracingConfig()

def initialize_tracing(service_name: str = "supply-chain-agent", 
                      jaeger_host: Optional[str] = None,
                      jaeger_port: int = 6831,
                      enable_console_exporter: bool = None):
    """Initialize the global tracing configuration."""
    tracing_config.initialize(service_name, jaeger_host, jaeger_port, enable_console_exporter)

def get_tracer() -> trace.Tracer:
    """Get the global tracer instance."""
    return tracing_config.get_tracer()

def create_span(name: str, attributes: Optional[Dict[str, Any]] = None,
                parent_context: Optional[trace.SpanContext] = None) -> trace.Span:
    """Create a span using the global tracing configuration."""
    return tracing_config.create_span(name, attributes, parent_context)

@contextmanager
def span(name: str, attributes: Optional[Dict[str, Any]] = None,
         parent_context: Optional[trace.SpanContext] = None):
    """Context manager for creating spans using the global tracing configuration."""
    with tracing_config.span(name, attributes, parent_context) as span:
        yield span

def extract_context_from_headers(headers: Dict[str, str]) -> Optional[trace.SpanContext]:
    """Extract trace context from HTTP headers using the global tracing configuration."""
    return tracing_config.extract_context_from_headers(headers)

def inject_context_to_headers(context: trace.SpanContext) -> Dict[str, str]:
    """Inject trace context into HTTP headers using the global tracing configuration."""
    return tracing_config.inject_context_to_headers(context)

def add_event(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Add an event to the current span using the global tracing configuration."""
    tracing_config.add_event(name, attributes)

def set_attribute(key: str, value: Any):
    """Set an attribute on the current span using the global tracing configuration."""
    tracing_config.set_attribute(key, value)
