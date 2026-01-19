import React from 'react';
import MarkdownRenderer from './MarkdownRenderer';

/**
 * Test component to demonstrate markdown rendering
 * This can be used for testing and development
 */
const MarkdownTest = () => {
  const markdownExamples = [
    {
      title: 'Basic Markdown',
      content: `# Supply Chain Analysis

This is a **comprehensive analysis** of our supply chain optimization.

## Key Findings

- Cost reduction potential: **15-20%**
- Delivery time improvement: *2-3 days*
- Quality score: \`8.5/10\`

### Recommendations

1. **Supplier Diversification**
   - Add 2-3 new suppliers
   - Reduce dependency on single sources

2. **Inventory Optimization**
   - Implement JIT principles
   - Use \`demand forecasting\` algorithms

> **Note**: These recommendations are based on current market analysis and historical data.

\`\`\`python
# Example optimization code
def optimize_supply_chain(demand, suppliers):
    return min_cost_solution(demand, suppliers)
\`\`\`

[Learn more about supply chain optimization](https://example.com)`,
    },
    {
      title: 'Table Example',
      content: `## Cost Comparison

| Supplier | Cost | Quality | Lead Time |
|----------|------|---------|-----------|
| Supplier A | $100 | High | 2 weeks |
| Supplier B | $95 | Medium | 3 weeks |
| Supplier C | $110 | High | 1 week |

**Best option**: Supplier C for urgent orders, Supplier B for cost optimization.`,
    },
    {
      title: 'Mixed Content',
      content: `### Analysis Summary

This analysis covers:
- **Cost optimization** strategies
- *Delivery time* improvements  
- Quality assurance measures

\`\`\`
Total savings: $50,000
ROI: 300%
\`\`\`

> **Next Steps**: Implement phase 1 recommendations within 30 days.`,
    }
  ];

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Markdown Rendering Test</h1>
      <p className="text-gray-600">
        This component demonstrates the markdown rendering capabilities. 
        Each example shows different markdown features.
      </p>
      
      {markdownExamples.map((example, index) => (
        <div key={index} className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">{example.title}</h2>
          <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
            <MarkdownRenderer 
              content={example.content}
              className="max-w-none"
            />
          </div>
        </div>
      ))}
    </div>
  );
};

export default MarkdownTest;
