#!/usr/bin/env python3
"""Quick test script for tracing functionality."""

import sys
from pathlib import Path

# Add the app directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "app"))

from tracing_config import initialize_tracing, span, add_event, set_attribute, get_tracer


def test_basic_tracing():
    """Test basic tracing functionality."""
    print("🔗 Testing Basic Tracing Functionality...")
    print("=" * 60)
    
    try:
        # Initialize tracing
        initialize_tracing(
            service_name="test-supply-chain-backend",
            enable_console_exporter=True
        )
        print("✅ Tracing Initialized!")
        
        # Test basic tracing functionality
        tracer = get_tracer()
        print(f"✅ Tracer Created: {tracer}")
        
        # Test span creation
        with span("test_basic_span") as span_obj:
            print(f"✅ Test Span Created: {span_obj}")
            add_event("test_event", {"message": "Hello from tracing test!"})
            set_attribute("test.attribute", "test_value")
            print("✅ Span Events and Attributes Added!")
        
        # Test multiple spans
        print("\n🔗 Testing Multiple Spans:")
        with span("parent_span") as parent_span:
            print(f"  Parent Span: {parent_span}")
            add_event("parent_event")
            
            # Create child span
            with span("child_span") as child_span:
                print(f"  Child Span: {child_span}")
                add_event("child_event")
                set_attribute("child.attribute", "child_value")
        
        print("✅ Multiple Spans Test Completed!")
        return True
        
    except Exception as e:
        print(f"❌ Error testing basic tracing: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("🚀 Quick Tracing Test")
    print("=" * 60)
    
    success = test_basic_tracing()
    
    if success:
        print("\n🎯 All tests passed! Tracing is working correctly.")
    else:
        print("\n❌ Some tests failed. Check the output above.")
        sys.exit(1)
