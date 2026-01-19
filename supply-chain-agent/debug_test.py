#!/usr/bin/env python3
"""Simple debug test for market analysis integration."""

import asyncio
from agent_executor import SupplyChainOptimizerAgent

async def test_market_analysis():
    """Test the market analysis integration directly."""
    print("🧪 Testing Market Analysis Integration Directly")
    print("=" * 60)
    
    agent = SupplyChainOptimizerAgent()
    
    # Test 1: Regular request
    print("\n📋 Test 1: Regular Request")
    print("-" * 40)
    result1 = await agent.invoke("optimize laptop supply chain")
    print(f"Result: {result1[:200]}...")
    
    # Test 2: Market analysis request
    print("\n🔗 Test 2: Market Analysis Request")
    print("-" * 40)
    result2 = await agent.invoke("perform market analysis for laptop supply chain optimization")
    print(f"Result: {result2[:200]}...")
    
    # Test 3: Check if results are different
    print("\n🔍 Test 3: Comparison")
    print("-" * 40)
    if result1 == result2:
        print("❌ Results are identical - market analysis not working")
    else:
        print("✅ Results are different - market analysis working!")
        print(f"Length difference: {len(result2) - len(result1)} characters")

if __name__ == "__main__":
    asyncio.run(test_market_analysis())
