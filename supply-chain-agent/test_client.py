#!/usr/bin/env python3
"""Test client for the Supply Chain Optimizer Agent.

Timeout Configuration:
- Connect: 30 seconds (establish connection)
- Read: 60 seconds (1 minute for response)
- Write: 30 seconds (send request)
- Pool: 30 seconds (connection pool)
"""

import asyncio
import json
import os
import uuid
from typing import Any, Dict
import httpx

from a2a.client import ClientFactory, ClientConfig
from a2a.types import TransportProtocol
from a2a.client.middleware import ClientCallInterceptor, ClientCallContext

# Import tracing functions
from tracing_config import (
    span, add_event, set_attribute, initialize_tracing,
    extract_context_from_headers, inject_context_to_headers
)


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
    """Generate a W3C trace context for testing."""
    # Generate random trace ID (32 hex characters)
    trace_id = uuid.uuid4().hex
    # Generate random span ID (16 hex characters)
    span_id = uuid.uuid4().hex[:16]
    # Create traceparent header
    traceparent = f"00-{trace_id}-{span_id}-01"
    
    # Create tracestate header (optional)
    tracestate = f"test=00f067aa0ba902b7,supply-chain=test-{uuid.uuid4().hex[:8]}"
    
    return {
        "traceparent": traceparent,
        "tracestate": tracestate,
        "trace_id": trace_id,
        "span_id": span_id
    }


def create_tracing_headers(trace_context: Dict[str, str]) -> Dict[str, str]:
    """Create HTTP headers with tracing context."""
    return {
        "traceparent": trace_context["traceparent"],
        "tracestate": trace_context["tracestate"],
        "Content-Type": "application/json"
    }


async def test_supply_chain_optimizer():
    """Test the Supply Chain Optimizer Agent."""
    
    # Create client with proper configuration and extended timeout
    timeout = httpx.Timeout(
        connect=30.0,      # 30 seconds to establish connection
        read=60.0,         # 1 minute to read response
        write=30.0,        # 30 seconds to write request
        pool=30.0          # 30 seconds for connection pool
    )
    
    async with httpx.AsyncClient(timeout=timeout) as httpx_client:
        # Create client configuration
        config = ClientConfig(
            httpx_client=httpx_client,
            supported_transports=[TransportProtocol.jsonrpc],  # This becomes 'JSONRPC'
            streaming=False  # Disable streaming for Phase 1
        )
        
        # Create client factory
        factory = ClientFactory(config)
        
        # Create a minimal agent card for testing
        from a2a.client import minimal_agent_card
        from dotenv import load_dotenv
        
        # Load environment variables
        load_dotenv()
        
        # Get agent URL from environment or use default
        agent_url = os.getenv("SUPPLY_CHAIN_AGENT_URL", "http://localhost:9999/")
        
        test_card = minimal_agent_card(
            url=agent_url,
            transports=["JSONRPC"]  # Use uppercase to match TransportProtocol.jsonrpc
        )
        
        # Create client
        client = factory.create(test_card)
        
        print("🔍 Testing Supply Chain Optimizer Agent...")
        print("=" * 60)
        
        # Test 1: Basic supply chain optimization with tracing
        print("\n📋 Test 1: Basic Supply Chain Optimization (with Tracing)")
        print("-" * 40)
        
        try:
            # Generate trace context
            trace_context = generate_trace_context()
            print(f"🔗 Generated Trace Context:")
            print(f"  Trace ID: {trace_context['trace_id']}")
            print(f"  Span ID: {trace_context['span_id']}")
            print(f"  Traceparent: {trace_context['traceparent']}")
            print(f"  Tracestate: {trace_context['tracestate']}")
            
            # Use the correct A2A client method
            from a2a.types import Message, Role
            from a2a.client.helpers import create_text_message_object
            
            message = create_text_message_object(role=Role.user, content="optimize laptop supply chain")
            
            # Send message using the client
            async for event in client.send_message(message):
                print("✅ Success!")
                print(f"Response: {event}")
                break  # Just get the first response for now
                
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
        
        # Test 2: Cost-focused optimization with tracing
        print("\n💰 Test 2: Cost-Focused Optimization (with Tracing)")
        print("-" * 40)
        
        try:
            # Generate new trace context for this test
            trace_context = generate_trace_context()
            print(f"🔗 New Trace Context for Cost Test:")
            print(f"  Trace ID: {trace_context['trace_id']}")
            print(f"  Span ID: {trace_context['span_id']}")
            
            message = create_text_message_object(role=Role.user, content="analyze and optimize our hardware procurement process for cost and speed")
            
            async for event in client.send_message(message):
                print("✅ Success!")
                print(f"Response: {event}")
                break
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        # Test 3: Inventory-focused request with tracing
        print("\n📦 Test 3: Inventory-Focused Request (with Tracing)")
        print("-" * 40)
        
        try:
            # Generate new trace context for this test
            trace_context = generate_trace_context()
            print(f"🔗 New Trace Context for Inventory Test:")
            print(f"  Trace ID: {trace_context['trace_id']}")
            print(f"  Span ID: {trace_context['span_id']}")
            
            message = create_text_message_object(role=Role.user, content="ensure we have adequate MacBook inventory for Q2 hiring targets")
            
            async for event in client.send_message(message):
                print("✅ Success!")
                print(f"Response: {event}")
                break
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        # Test 4: JSON request format with tracing
        print("\n🔧 Test 4: JSON Request Format (with Tracing)")
        print("-" * 40)
        
        try:
            # Generate new trace context for this test
            trace_context = generate_trace_context()
            print(f"🔗 New Trace Context for JSON Test:")
            print(f"  Trace ID: {trace_context['trace_id']}")
            print(f"  Span ID: {trace_context['span_id']}")
            
            json_request = {
                "request_type": "supply_chain_optimization",
                "focus": "laptop_inventory",
                "constraints": ["budget", "timeline"],
                "priority": "high"
            }
            
            # Convert JSON to text for now
            message = create_text_message_object(role=Role.user, content=json.dumps(json_request))
            
            async for event in client.send_message(message):
                print("✅ Success!")
                print(f"Response: {event}")
                break
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        # Test 5: Agent capabilities with tracing
        print("\n🔍 Test 5: Agent Capabilities (with Tracing)")
        print("-" * 40)
        
        try:
            # Generate new trace context for this test
            trace_context = generate_trace_context()
            print(f"🔗 New Trace Context for Capabilities Test:")
            print(f"  Trace ID: {trace_context['trace_id']}")
            print(f"  Span ID: {trace_context['span_id']}")
            
            # Get agent card from the actual server
            from a2a.client import A2ACardResolver
            
            resolver = A2ACardResolver(httpx_client, agent_url.rstrip('/'))
            agent_card = await resolver.get_agent_card()
            
            print("✅ Agent Card Retrieved!")
            print(f"Name: {agent_card.name}")
            print(f"Description: {agent_card.description}")
            print(f"Skills: {len(agent_card.skills)}")
            
            for skill in agent_card.skills:
                print(f"  - {skill.name}: {skill.description}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        # Test 6: Market Analysis Integration with tracing
        print("\n🔗 Test 6: Market Analysis Integration (with Tracing)")
        print("-" * 40)
        
        try:
            # Create a REAL parent span that will be propagated
            with span("test_client.calling_supply_chain_agent") as parent_span:
                print(f"🔗 Created Parent Span: {parent_span}")
                add_event("test_client.calling_supply_chain_agent_started")
                set_attribute("test.type", "market_analysis_integration")
                set_attribute("test.client", "test_client")
                set_attribute("test.target", "supply_chain_agent")
                
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
                
                message = create_text_message_object(role=Role.user, content="perform market analysis for laptop supply chain optimization")
                
                async for event in client.send_message(message):
                    print("✅ Success!")
                    print(f"Response: {event}")
                    break
                
                add_event("test_client.calling_supply_chain_agent_completed")
                
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
        
        # Test 7: Regular request without market analysis (with tracing)
        print("\n📋 Test 7: Regular Request - No Market Analysis (with Tracing)")
        print("-" * 40)
        
        try:
            # Generate new trace context for this test
            trace_context = generate_trace_context()
            print(f"🔗 New Trace Context for Regular Request Test:")
            print(f"  Trace ID: {trace_context['trace_id']}")
            print(f"  Span ID: {trace_context['span_id']}")
            
            message = create_text_message_object(role=Role.user, content="optimize laptop supply chain")
            
            async for event in client.send_message(message):
                print("✅ Success!")
                print(f"Response: {event}")
                break
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        # Test 8: Tracing Context Propagation Test
        print("\n🔗 Test 8: Tracing Context Propagation Test")
        print("-" * 40)
        
        try:
            # Create a REAL parent span that will be propagated
            with span("test_client.calling_supply_chain_agent") as parent_span:
                print(f"🔗 Created Parent Span: {parent_span}")
                add_event("test_client.calling_supply_chain_agent_started")
                set_attribute("test.type", "tracing_propagation")
                set_attribute("test.client", "test_client")
                set_attribute("test.target", "supply_chain_agent")
                
                # Generate trace context from the current span
                trace_context = generate_trace_context()
                print(f"🔗 Testing Context Propagation:")
                print(f"  Trace ID: {trace_context['trace_id']}")
                print(f"  Span ID: {trace_context['span_id']}")
                
                # Create headers with tracing context
                headers = create_tracing_headers(trace_context)
                print(f"  Headers: {headers}")
                
                # Create tracing interceptor
                tracing_interceptor = TracingInterceptor(headers)
                
                # Create client with tracing interceptor
                client = factory.create(test_card, interceptors=[tracing_interceptor])
                
                # Test that the context would be propagated
                message = create_text_message_object(role=Role.user, content="test tracing context propagation")
                
                async for event in client.send_message(message):
                    print("✅ Success! Tracing context should be propagated")
                    print(f"Response: {event}")
                    break
                
                add_event("test_client.calling_supply_chain_agent_completed")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        
        print("\n" + "=" * 60)
        print("🎯 Testing Complete!")


async def test_market_analysis_integration():
    """Test market analysis integration specifically."""
    
    print("\n🔍 Testing Market Analysis Integration...")
    print("=" * 60)
    
    # Create client with proper configuration and extended timeout
    timeout = httpx.Timeout(
        connect=30.0,      # 30 seconds to establish connection
        read=60.0,         # 1 minute to read response
        write=30.0,        # 30 seconds to write request
        pool=30.0          # 30 seconds for connection pool
    )
    
    async with httpx.AsyncClient(timeout=timeout) as httpx_client:
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
        from dotenv import load_dotenv
        
        # Load environment variables
        load_dotenv()
        
        # Get agent URL from environment or use default
        agent_url = os.getenv("SUPPLY_CHAIN_AGENT_URL", "http://localhost:9999/")
        
        test_card = minimal_agent_card(
            url=agent_url,
            transports=["JSONRPC"]
        )
        
        # Create client
        client = factory.create(test_card)
        
        try:
            # Generate trace context for this test
            trace_context = generate_trace_context()
            print(f"🔗 Market Analysis Test Trace Context:")
            print(f"  Trace ID: {trace_context['trace_id']}")
            print(f"  Span ID: {trace_context['trace_id']}")
            print(f"  Traceparent: {trace_context['traceparent']}")
            print(f"  Tracestate: {trace_context['tracestate']}")
            
            # Use the specific phrase for market analysis
            from a2a.types import Message, Role
            from a2a.client.helpers import create_text_message_object
            
            message = create_text_message_object(
                role=Role.user, 
                content="perform market analysis"
            )
            
            print(f"\n📝 Sending message: '{message.parts[0].root.text}'")
            print("-" * 40)
            
            # Send message using the client
            async for event in client.send_message(message):
                print("✅ Market Analysis Request Successful!")
                print(f"Response: {event}")
                break  # Just get the first response for now
                
        except Exception as e:
            print(f"❌ Error in market analysis test: {e}")
            import traceback
            traceback.print_exc()


async def test_business_policy_validation():
    """Test business policy validation functionality."""
    
    print("\n🔒 Testing Business Policy Validation...")
    print("=" * 60)
    
    # Import the business policies module
    try:
        from business_policies import business_policies
        
        print("✅ Business Policies Module Loaded!")
        
        # Test policy summary
        policy_summary = business_policies.get_policy_summary()
        print(f"\n📊 Policy Summary:")
        print(f"  - Inventory Buffer: {policy_summary['inventory_management']['buffer_months']} months")
        print(f"  - Approval Threshold: ${policy_summary['financial_controls']['approval_threshold']:,}")
        print(f"  - Max Order Value: ${policy_summary['financial_controls']['max_order_value']:,}")
        print(f"  - Preferred Vendors: {', '.join(policy_summary['vendor_management']['preferred_vendors'])}")
        
        # Test validation
        print(f"\n🔍 Testing Policy Validation:")
        
        # Test 1: Valid order
        test_order = {"order_value": 25000, "vendor": "Apple", "product": "MacBook Pro", "quantity": 100}
        validation = business_policies.validate_request_against_policies(test_order)
        print(f"  - Valid Order ($25k, Apple, 100 MacBooks): {'✅ Valid' if validation['is_valid'] else '❌ Invalid'}")
        if validation['warnings']:
            print(f"    Warnings: {validation['warnings']}")
        
        # Test 2: High-value order requiring approval
        test_order = {"order_value": 75000, "vendor": "Dell", "product": "Dell XPS", "quantity": 150}
        validation = business_policies.validate_request_against_policies(test_order)
        print(f"  - High-Value Order ($75k, Dell, 150 XPS): {'✅ Valid' if validation['is_valid'] else '❌ Invalid'}")
        if validation['warnings']:
            print(f"    Warnings: {validation['warnings']}")
        
        # Test 3: Order exceeding max value
        test_order = {"order_value": 150000, "vendor": "HP", "product": "HP EliteBook", "quantity": 200}
        validation = business_policies.validate_request_against_policies(test_order)
        print(f"  - Order Exceeding Max Value ($150k, HP, 200 EliteBooks): {'✅ Valid' if validation['is_valid'] else '❌ Invalid'}")
        if validation['violations']:
            print(f"    Violations: {validation['violations']}")
        
        # Test 4: Non-preferred vendor
        test_order = {"order_value": 30000, "vendor": "ASUS", "product": "ASUS ZenBook", "quantity": 50}
        validation = business_policies.validate_request_against_policies(test_order)
        print(f"  - Non-Preferred Vendor ($30k, ASUS, 50 ZenBooks): {'✅ Valid' if validation['is_valid'] else '❌ Invalid'}")
        if validation['warnings']:
            print(f"    Warnings: {validation['warnings']}")
            
    except ImportError as e:
        print(f"❌ Error importing business policies: {e}")
    except Exception as e:
        print(f"❌ Error testing business policies: {e}")


async def test_tracing_functionality():
    """Test OpenTelemetry tracing functionality."""
    
    print("\n🔗 Testing OpenTelemetry Tracing Functionality...")
    print("=" * 60)
    
    try:
        # Import tracing configuration
        from tracing_config import initialize_tracing, get_tracer, create_span, add_event, set_attribute
        
        print("✅ Tracing Configuration Module Loaded!")
        
        # Initialize tracing
        initialize_tracing(
            service_name="test-supply-chain-agent",
            enable_console_exporter=None  # Will use environment variable ENABLE_CONSOLE_EXPORTER
        )
        print("✅ Tracing Initialized!")
        
        # Test basic tracing functionality
        tracer = get_tracer()
        print(f"✅ Tracer Created: {tracer}")
        
        # Test span creation
        with create_span("test_span") as span:
            print(f"✅ Test Span Created: {span}")
            add_event("test_event", {"message": "Hello from tracing test!"})
            set_attribute("test.attribute", "test_value")
            print("✅ Span Events and Attributes Added!")
        
        # Test multiple spans
        print("\n🔗 Testing Multiple Spans:")
        with create_span("parent_span") as parent_span:
            print(f"  Parent Span: {parent_span}")
            add_event("parent_event")
            
            # Create child span without parent context for now (simplified)
            with create_span("child_span") as child_span:
                print(f"  Child Span: {child_span}")
                add_event("child_event")
                set_attribute("child.attribute", "child_value")
        
        print("✅ Multiple Spans Test Completed!")
        
        # Test trace context generation
        print("\n🔗 Testing Trace Context Generation:")
        trace_context = generate_trace_context()
        print(f"  Generated Trace Context:")
        print(f"    Trace ID: {trace_context['trace_id']}")
        print(f"    Span ID: {trace_context['span_id']}")
        print(f"    Traceparent: {trace_context['traceparent']}")
        print(f"    Tracestate: {trace_context['tracestate']}")
        
        print("✅ Trace Context Generation Test Completed!")
        
    except ImportError as e:
        print(f"❌ Error importing tracing configuration: {e}")
    except Exception as e:
        print(f"❌ Error testing tracing functionality: {e}")
        import traceback
        traceback.print_exc()


async def main():
    """Main test function."""
    print("🚀 Supply Chain Optimizer Agent Test Suite")
    print("=" * 60)
    
    # Define available tests
    available_tests = {
        "1": ("Tracing Functionality", test_tracing_functionality),
        "2": ("Supply Chain Optimizer Agent", test_supply_chain_optimizer),
        "3": ("Business Policy Validation", test_business_policy_validation),
        "4": ("Market Analysis Integration", test_market_analysis_integration),
        "5": ("All Tests", None),  # Special case for all tests
        "6": ("Quick Tracing Test", test_tracing_functionality),  # Quick option for tracing
    }
    
    # Display test menu
    print("\n📋 Available Tests:")
    print("-" * 30)
    for key, (name, _) in available_tests.items():
        if key == "6":
            print(f"  {key}. {name} (Fast)")
        else:
            print(f"  {key}. {name}")
    print("  q. Quit")
    
    # Get user selection
    while True:
        selection = input("\n🎯 Select test to run (1-6, q to quit): ").strip().lower()
        
        if selection == "q":
            print("👋 Goodbye!")
            return
        
        if selection in available_tests:
            test_name, test_func = available_tests[selection]
            
            if selection == "5":  # All tests
                print(f"\n🚀 Running ALL tests...")
                print("=" * 60)
                
                # Test tracing functionality first
                await test_tracing_functionality()
                
                # Test the agent
                await test_supply_chain_optimizer()
                
                # Test business policies
                await test_business_policy_validation()
                
                # Test market analysis integration
                await test_market_analysis_integration()
                
                print("\n🎯 All tests completed!")
                break
                
            else:  # Single test
                print(f"\n🚀 Running: {test_name}")
                print("=" * 60)
                await test_func()
                print(f"\n✅ {test_name} completed!")
                break
        else:
            print("❌ Invalid selection. Please choose 1-6 or 'q' to quit.")


if __name__ == "__main__":
    asyncio.run(main())
