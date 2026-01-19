#!/usr/bin/env python3
"""Test client for the Market Analysis Agent.

Timeout Configuration:
- Connect: 30 seconds (establish connection)
- Read: 60 seconds (1 minute for response)
- Write: 30 seconds (send request)
- Pool: 30 seconds (connection pool)
"""

import asyncio
import json
import uuid
from typing import Any, Dict
import httpx
from dotenv import load_dotenv

from a2a.client import ClientFactory, ClientConfig
from a2a.types import TransportProtocol
from a2a.client.middleware import ClientCallInterceptor, ClientCallContext

# Import tracing functions
from tracing_config import (
    span, add_event, set_attribute, initialize_tracing,
    extract_context_from_headers, inject_context_to_headers
)

# Load environment variables
load_dotenv()

def create_httpx_client():
    """Create an httpx client with proper timeout configuration."""
    timeout = httpx.Timeout(
        connect=30.0,      # 30 seconds to establish connection
        read=60.0,         # 1 minute to read response
        write=30.0,        # 30 seconds to write request
        pool=30.0          # 30 seconds for connection pool
    )
    return httpx.AsyncClient(timeout=timeout)

class TracingInterceptor(ClientCallInterceptor):
    """Interceptor that injects trace context into HTTP requests."""
    
    def __init__(self, trace_headers: Dict[str, str]):
        self.trace_headers = trace_headers
    
    async def intercept(
        self,
        method_name: str,
        request_payload: dict[str, Any],
        http_kwargs: dict[str, Any],
        agent_card: Any | None,
        context: ClientCallContext | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Inject trace headers into the HTTP request."""
        headers = http_kwargs.get('headers', {})
        headers.update(self.trace_headers)
        http_kwargs['headers'] = headers
        print(f"🔗 TracingInterceptor: Injected headers: {self.trace_headers}")
        return request_payload, http_kwargs

def generate_trace_context():
    """Generate a new trace context for testing."""
    trace_id = uuid.uuid4().hex
    span_id = uuid.uuid4().hex[:16]
    
    trace_context = {
        "trace_id": trace_id,
        "span_id": span_id,
        "traceparent": f"00-{trace_id}-{span_id}-01",
        "tracestate": f"test={uuid.uuid4().hex[:16]},market-analysis={uuid.uuid4().hex[:16]}"
    }
    
    return trace_context

def create_tracing_headers(trace_context: Dict[str, str]) -> Dict[str, str]:
    """Create HTTP headers for trace context propagation."""
    return {
        "traceparent": trace_context["traceparent"],
        "tracestate": trace_context["tracestate"]
    }

async def test_tracing_functionality():
    """Test the OpenTelemetry tracing functionality."""
    print("🔗 Testing OpenTelemetry Tracing Functionality...")
    print("=" * 60)
    
    try:
        # Initialize tracing
        initialize_tracing(
            service_name="market-analysis-agent-test",
            enable_console_exporter=True
        )
        print("✅ Tracing Initialized!")
        
        # Test basic span creation
        print("\n🔗 Testing Basic Span Creation:")
        with span("test_span") as test_span:
            print(f"  Test Span: {test_span}")
            add_event("test_event")
            set_attribute("test.attribute", "test_value")
            print("✅ Basic span creation successful!")
        
        # Test multiple spans
        print("\n🔗 Testing Multiple Spans:")
        with span("parent_span") as parent_span:
            print(f"  Parent Span: {parent_span}")
            add_event("parent_event")
            
            # Create child span without parent context for now (simplified)
            with span("child_span") as child_span:
                print(f"  Child Span: {child_span}")
                add_event("child_event")
                set_attribute("child.attribute", "child_value")
        
        print("✅ Multiple spans test successful!")
        
        # Test trace context generation
        print("\n🔗 Testing Trace Context Generation:")
        trace_context = generate_trace_context()
        print(f"  Trace ID: {trace_context['trace_id']}")
        print(f"  Span ID: {trace_context['span_id']}")
        print(f"  Traceparent: {trace_context['traceparent']}")
        print(f"  Tracestate: {trace_context['tracestate']}")
        print("✅ Trace context generation successful!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing tracing functionality: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_basic_inventory_analysis():
    """Test basic inventory demand analysis."""
    print("📊 Test: Basic Inventory Demand Analysis")
    print("-" * 40)
    
    # Create client with proper configuration and timeout
    async with create_httpx_client() as httpx_client:
        # Create client configuration
        config = ClientConfig(
            httpx_client=httpx_client,
            supported_transports=[TransportProtocol.jsonrpc],
            streaming=False
        )
        
        # Create client factory
        factory = ClientFactory(config)
        
        # Create a minimal agent card for testing
        from a2a.client import minimal_agent_card
        test_card = minimal_agent_card(
            url="http://localhost:9998/",
            transports=["JSONRPC"]
        )
        
        # Create a basic client
        client = factory.create(test_card)
        
        try:
            from a2a.types import Message, Role
            from a2a.client.helpers import create_text_message_object
            
            message = create_text_message_object(role=Role.user, content="analyze laptop demand and inventory for engineering, sales, marketing, and operations teams")
            
            async for event in client.send_message(message):
                print("✅ Success!")
                print(f"Response: {event}")
                break
                
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()

async def test_market_trend_forecasting():
    """Test market trend forecasting."""
    print("📈 Test: Market Trend Forecasting")
    print("-" * 40)
    
    # Create client with proper configuration and timeout
    async with create_httpx_client() as httpx_client:
        # Create client configuration
        config = ClientConfig(
            httpx_client=httpx_client,
            supported_transports=[TransportProtocol.jsonrpc],
            streaming=False
        )
        
        # Create client factory
        factory = ClientFactory(config)
        
        # Create a minimal agent card for testing
        from a2a.client import minimal_agent_card
        test_card = minimal_agent_card(
            url="http://localhost:9998/",
            transports=["JSONRPC"]
        )
        
        # Create a basic client
        client = factory.create(test_card)
        
        try:
            from a2a.types import Message, Role
            from a2a.client.helpers import create_text_message_object
            
            message = create_text_message_object(role=Role.user, content="forecast laptop market trends and pricing for the next 6 months")
            
            async for event in client.send_message(message):
                print("✅ Success!")
                print(f"Response: {event}")
                break
                
        except Exception as e:
            print(f"❌ Error: {e}")

async def test_demand_pattern_modeling():
    """Test demand pattern modeling."""
    print("👥 Test: Demand Pattern Modeling")
    print("-" * 40)
    
    # Create client with proper configuration and timeout
    async with create_httpx_client() as httpx_client:
        # Create client configuration
        config = ClientConfig(
            httpx_client=httpx_client,
            supported_transports=[TransportProtocol.jsonrpc],
            streaming=False
        )
        
        # Create client factory
        factory = ClientFactory(config)
        
        # Create a minimal agent card for testing
        from a2a.client import minimal_agent_card
        test_card = minimal_agent_card(
            url="http://localhost:9998/",
            transports=["JSONRPC"]
        )
        
        # Create a basic client
        client = factory.create(test_card)
        
        try:
            from a2a.types import Message, Role
            from a2a.client.helpers import create_text_message_object
            
            message = create_text_message_object(role=Role.user, content="model laptop demand patterns for engineering and sales teams over the next 6 months")
            
            async for event in client.send_message(message):
                print("✅ Success!")
                print(f"Response: {event}")
                break
                
        except Exception as e:
            print(f"❌ Error: {e}")

async def test_comprehensive_analysis():
    """Test comprehensive market analysis."""
    print("🔍 Test: Comprehensive Market Analysis")
    print("-" * 40)
    
    # Create client with proper configuration and timeout
    async with create_httpx_client() as httpx_client:
        # Create client configuration
        config = ClientConfig(
            httpx_client=httpx_client,
            supported_transports=[TransportProtocol.jsonrpc],
            streaming=False
        )
        
        # Create client factory
        factory = ClientFactory(config)
        
        # Create a minimal agent card for testing
        from a2a.client import minimal_agent_card
        test_card = minimal_agent_card(
            url="http://localhost:9998/",
            transports=["JSONRPC"]
        )
        
        # Create a basic client
        client = factory.create(test_card)
        
        try:
            from a2a.types import Message, Role
            from a2a.client.helpers import create_text_message_object
            
            message = create_text_message_object(role=Role.user, content="provide a comprehensive market analysis including inventory, trends, and demand patterns")
            
            async for event in client.send_message(message):
                print("✅ Success!")
                print(f"Response: {event}")
                break
                
        except Exception as e:
            print(f"❌ Error: {e}")

async def test_tracing_context_propagation():
    """Test tracing context propagation."""
    print("🔗 Test: Tracing Context Propagation")
    print("-" * 40)
    
    # Create client with proper configuration and timeout
    async with create_httpx_client() as httpx_client:
        # Create client configuration
        config = ClientConfig(
            httpx_client=httpx_client,
            supported_transports=[TransportProtocol.jsonrpc],
            streaming=False
        )
        
        # Create client factory
        factory = ClientFactory(config)
        
        # Create a minimal agent card for testing
        from a2a.client import minimal_agent_card
        test_card = minimal_agent_card(
            url="http://localhost:9998/",
            transports=["JSONRPC"]
        )
        
        try:
            # Create a REAL parent span that will be propagated
            with span("test_client.calling_market_analysis_agent") as parent_span:
                print(f"🔗 Created Parent Span: {parent_span}")
                add_event("test_client.calling_market_analysis_agent_started")
                set_attribute("test.type", "tracing_propagation")
                set_attribute("test.client", "test_client")
                set_attribute("test.target", "market_analysis_agent")
                
                # Generate trace context from the current span
                trace_context = generate_trace_context()
                print(f"🔗 Generated Trace Context:")
                print(f"  Trace ID: {trace_context['trace_id']}")
                print(f"  Span ID: {trace_context['span_id']}")
                print(f"  Traceparent: {trace_context['traceparent']}")
                print(f"  Tracestate: {trace_context['tracestate']}")
                
                # Create tracing headers
                tracing_headers = create_tracing_headers(trace_context)
                print(f"🔗 Created Tracing Headers: {tracing_headers}")
                
                # Create tracing interceptor
                tracing_interceptor = TracingInterceptor(tracing_headers)
                
                # Create client with tracing interceptor
                client = factory.create(test_card, interceptors=[tracing_interceptor])
                
                # Create message with tracing context
                from a2a.types import Message, Role
                from a2a.client.helpers import create_text_message_object
                
                message = create_text_message_object(
                    role=Role.user, 
                    content="perform market analysis with tracing context"
                )
                
                print(f"\n📝 Sending message: '{message.parts[0].root.text}'")
                print("-" * 40)
                
                async for event in client.send_message(message):
                    print("✅ Success!")
                    print(f"Response: {event}")
                    break
                
                add_event("test_client.calling_market_analysis_agent_completed")
        
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()

async def test_agent_capabilities():
    """Test agent capabilities."""
    print("🔍 Test: Agent Capabilities")
    print("-" * 40)
    
    # Create client with proper configuration and timeout
    async with create_httpx_client() as httpx_client:
        try:
            # Get agent card from the actual server
            from a2a.client import A2ACardResolver
            
            resolver = A2ACardResolver(httpx_client, "http://localhost:9998")
            agent_card = await resolver.get_agent_card()
            
            print("✅ Agent Card Retrieved!")
            print(f"Name: {agent_card.name}")
            print(f"Description: {agent_card.description}")
            print(f"Skills: {len(agent_card.skills)}")
            
            for skill in agent_card.skills:
                print(f"  - {skill.name}: {skill.description}")
                
        except Exception as e:
            print(f"❌ Error: {e}")

async def test_market_analysis_agent():
    """Test the Market Analysis Agent with all test cases."""
    print("🔍 Testing Market Analysis Agent...")
    print("=" * 60)
    
    # Run all individual tests
    await test_basic_inventory_analysis()
    await test_market_trend_forecasting()
    await test_demand_pattern_modeling()
    await test_comprehensive_analysis()
    await test_tracing_context_propagation()
    await test_agent_capabilities()
    
    print("\n" + "=" * 60)
    print("🎯 All Market Analysis Agent Tests Complete!")
    return True

async def main():
    """Main test function."""
    print("🚀 Market Analysis Agent Test Suite")
    print("=" * 60)
    
    # Define available tests
    available_tests = {
        "1": ("Tracing Functionality", test_tracing_functionality),
        "2": ("Basic Inventory Analysis", test_basic_inventory_analysis),
        "3": ("Market Trend Forecasting", test_market_trend_forecasting),
        "4": ("Demand Pattern Modeling", test_demand_pattern_modeling),
        "5": ("Comprehensive Analysis", test_comprehensive_analysis),
        "6": ("Tracing Context Propagation", test_tracing_context_propagation),
        "7": ("Agent Capabilities", test_agent_capabilities),
        "8": ("All Tests", test_market_analysis_agent),
        "9": ("Quick Tracing Test", test_tracing_functionality),  # Quick option for tracing
    }
    
    # Display test menu
    print("\n📋 Available Tests:")
    print("-" * 30)
    for key, (name, _) in available_tests.items():
        if key == "9":
            print(f"  {key}. {name} (Fast)")
        else:
            print(f"  {key}. {name}")
    print("  q. Quit")
    
    # Get user selection
    while True:
        selection = input("\n🎯 Select test to run (1-9, q to quit): ").strip().lower()
        
        if selection == "q":
            print("👋 Goodbye!")
            return
        
        if selection in available_tests:
            test_name, test_func = available_tests[selection]
            
            print(f"\n🚀 Running: {test_name}")
            print("=" * 60)
            await test_func()
            print(f"\n✅ {test_name} completed!")
            break
        else:
            print("❌ Invalid selection. Please choose 1-9 or 'q' to quit.")


if __name__ == "__main__":
    asyncio.run(main())
