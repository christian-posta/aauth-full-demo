import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { isMarkdown } from '../utils/markdownUtils';

/**
 * Component that renders content as markdown if detected, otherwise as plain text
 */
const MarkdownRenderer = ({ content, className = '', showToggle = true }) => {
  const [isExpanded, setIsExpanded] = React.useState(false);
  const [isMarkdownContent, setIsMarkdownContent] = React.useState(false);

  React.useEffect(() => {
    if (content) {
      setIsMarkdownContent(isMarkdown(content));
    }
  }, [content]);

  if (!content) {
    return null;
  }

  // If it's not markdown, render as plain text
  if (!isMarkdownContent) {
    return (
      <div className={`whitespace-pre-wrap text-gray-800 font-mono text-sm leading-relaxed ${className}`}>
        {content}
      </div>
    );
  }

  // For markdown content, provide toggle functionality for long content
  const shouldShowToggle = showToggle && content.length > 500;
  const displayContent = shouldShowToggle && !isExpanded 
    ? content.substring(0, 500) + '...' 
    : content;

  return (
    <div className={`markdown-content ${className}`}>
      <div className="prose prose-sm max-w-none prose-headings:text-gray-900 prose-p:text-gray-700 prose-strong:text-gray-900 prose-code:text-gray-800 prose-pre:bg-gray-100 prose-pre:border prose-pre:border-gray-200">
        <ReactMarkdown 
          remarkPlugins={[remarkGfm]}
          components={{
            // Customize code blocks
            code: ({ node, inline, className, children, ...props }) => {
              const match = /language-(\w+)/.exec(className || '');
              return !inline ? (
                <pre className="bg-gray-100 border border-gray-200 rounded-lg p-3 overflow-x-auto">
                  <code className={className} {...props}>
                    {children}
                  </code>
                </pre>
              ) : (
                <code className="bg-gray-100 px-1 py-0.5 rounded text-sm font-mono" {...props}>
                  {children}
                </code>
              );
            },
            // Customize tables
            table: ({ children }) => (
              <div className="overflow-x-auto">
                <table className="min-w-full border border-gray-200 rounded-lg">
                  {children}
                </table>
              </div>
            ),
            th: ({ children }) => (
              <th className="border border-gray-200 px-3 py-2 bg-gray-50 text-left text-sm font-medium text-gray-900">
                {children}
              </th>
            ),
            td: ({ children }) => (
              <td className="border border-gray-200 px-3 py-2 text-sm text-gray-700">
                {children}
              </td>
            ),
            // Customize blockquotes
            blockquote: ({ children }) => (
              <blockquote className="border-l-4 border-blue-500 pl-4 italic text-gray-700 bg-blue-50 py-2 rounded-r">
                {children}
              </blockquote>
            ),
            // Customize lists
            ul: ({ children }) => (
              <ul className="list-disc list-inside space-y-1 text-gray-700">
                {children}
              </ul>
            ),
            ol: ({ children }) => (
              <ol className="list-decimal list-inside space-y-1 text-gray-700">
                {children}
              </ol>
            ),
            // Customize links
            a: ({ href, children }) => (
              <a 
                href={href} 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-blue-600 hover:text-blue-800 underline"
              >
                {children}
              </a>
            ),
          }}
        >
          {displayContent}
        </ReactMarkdown>
      </div>
      
      {shouldShowToggle && (
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="mt-3 text-sm text-blue-600 hover:text-blue-800 underline focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded"
        >
          {isExpanded ? 'Show Less' : 'Show More'}
        </button>
      )}
    </div>
  );
};

export default MarkdownRenderer;
