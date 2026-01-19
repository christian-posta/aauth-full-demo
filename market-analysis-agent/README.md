# Market Analysis Agent

A specialized A2A agent for analyzing laptop demand, inventory trends, and market conditions to optimize procurement decisions.

## Overview

The Market Analysis Agent is a domain expert that provides comprehensive analysis of laptop inventory needs, market trends, and employee demand patterns. It helps organizations make data-driven decisions about laptop procurement by analyzing current inventory levels against projected demand.

## Core Capabilities

### 1. Inventory Demand Analysis
- Analyzes current laptop inventory levels against projected demand
- Considers hiring plans, refresh cycles, and historical usage patterns
- Identifies inventory gaps and surplus situations
- Provides risk assessments and priority recommendations

### 2. Market Trend Forecasting
- Evaluates laptop market trends and pricing fluctuations
- Considers factors like new model releases, supply chain disruptions, and seasonal patterns
- Assesses market availability risks for bulk orders
- Provides impact assessments for different market scenarios

### 3. Demand Pattern Modeling
- Models laptop demand patterns based on department growth and role requirements
- Factors in different laptop specifications needed by various teams
- Calculates optimal mix of laptop models based on department preferences
- Projects demand over configurable timeframes

## What It Does

The agent receives delegation requests like "Analyze laptop demand and inventory" and:

1. **Calls Inventory MCP Server** to get current stock levels
2. **Calls HR/Planning MCP Server** to get hiring forecasts
3. **Analyzes patterns** and generates demand forecasts
4. **Returns structured analysis** with specific recommendations

Example output: "Need 25 more MacBook Pros, current inventory sufficient for MacBook Air"

## Usage

### Running the Agent

```bash
cd market-analysis-agent
python -m market_analysis_agent
```

### Programmatic Usage

```python
from agent_executor import market_analysis_executor

# Execute a market analysis
request = {
    "type": "analyze_laptop_demand",
    "timeframe_months": 6,
    "departments": ["engineering", "sales", "marketing"]
}

result = market_analysis_executor.execute_delegation(request)
print(result)
```

### Delegation Examples

The agent can handle various types of delegation requests:

- `"Analyze laptop demand and inventory"`
- `"Forecast laptop market trends for next quarter"`
- `"Model demand patterns for engineering team expansion"`
- `"Assess inventory gaps for upcoming hiring wave"`

## Configuration

### Department Preferences

The agent uses configurable department preferences for laptop models:

```python
department_preferences = {
    "engineering": {
        "MacBook Pro": 0.8,    # 80% prefer MacBook Pro
        "MacBook Air": 0.2     # 20% prefer MacBook Air
    },
    "sales": {
        "MacBook Pro": 0.3,    # 30% prefer MacBook Pro
        "MacBook Air": 0.7     # 70% prefer MacBook Air
    }
}
```

### Analysis Parameters

- **Default forecast months**: 6 months
- **Inventory buffer**: 3 months
- **Confidence threshold**: 70%
- **Surplus threshold**: 50% above required stock

## MCP Server Integration

The agent is designed to integrate with:

- **Inventory MCP Server**: For current stock levels and specifications
- **HR/Planning MCP Server**: For hiring forecasts and growth projections

Currently uses simulated data, but can be easily extended to call actual MCP servers.

## Output Format

The agent returns structured analysis results including:

- **Inventory Analysis**: Gaps, surplus, and risk assessment
- **Market Trends**: Identified trends with impact levels
- **Demand Patterns**: Department-specific demand projections
- **Recommendations**: Prioritized procurement actions with timelines
- **Cost Estimates**: Estimated costs for recommended actions

## Development

### Setup

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .
pip install -e ".[dev]"
```

### Testing

```bash
pytest tests/
```

### Code Quality

```bash
black .
isort .
mypy .
```

## Architecture

The agent follows a modular architecture:

- **`agent_executor.py`**: Main execution logic and workflow orchestration
- **`business_policies.py`**: Business rules and analysis algorithms
- **`agent_card.json`**: Agent capabilities and skill definitions
- **`__main__.py`**: Command-line interface and example usage

## Business Logic

The agent implements sophisticated business logic including:

- **Demand Calculation**: Combines hiring forecasts with department preferences
- **Buffer Management**: Maintains appropriate safety stock levels
- **Risk Assessment**: Evaluates inventory gaps and market risks
- **Recommendation Generation**: Provides actionable procurement guidance

## Future Enhancements

- Real-time MCP server integration
- Machine learning-based demand forecasting
- Advanced market data analysis
- Integration with procurement systems
- Historical trend analysis and learning

## License

This project is licensed under the same terms as the A2A framework.

## Contributing

Contributions are welcome! Please see the main A2A project for contribution guidelines.
