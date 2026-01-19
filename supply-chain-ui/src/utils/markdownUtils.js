/**
 * Utility functions for markdown detection and rendering
 */

/**
 * Detects if a string contains markdown formatting
 * @param {string} text - The text to analyze
 * @returns {boolean} - True if markdown is detected
 */
export const isMarkdown = (text) => {
  if (!text || typeof text !== 'string') {
    return false;
  }

  // Common markdown patterns
  const markdownPatterns = [
    /^#+\s+/m,                    // Headers (# ## ###)
    /\*\*.*?\*\*/,                // Bold (**text**)
    /\*.*?\*/,                    // Italic (*text*)
    /`.*?`/,                      // Inline code (`code`)
    /```[\s\S]*?```/,            // Code blocks (```code```)
    /\[.*?\]\(.*?\)/,            // Links [text](url)
    /^\s*[-*+]\s+/m,             // Unordered lists (- * +)
    /^\s*\d+\.\s+/m,             // Ordered lists (1. 2. 3.)
    /^\s*>\s+/m,                 // Blockquotes (> text)
    /^\|.*\|$/m,                 // Table rows (|col1|col2|)
    /^\s*`{3,}[\w]*$/m,         // Code block start (```language)
    /^\s*`{3,}$/m,              // Code block end (```)
    /^\s*[-*+]\s+\[[ xX]\]\s+/m, // Task lists (- [ ] task)
    /~~.*?~~/,                   // Strikethrough (~~text~~)
    /^\s*#{1,6}\s+.*$/m,        // ATX headers (# Header)
    /^\s*={3,}$/m,              // Setext headers (===)
    /^\s*-{3,}$/m,              // Horizontal rules (---)
  ];

  return markdownPatterns.some(pattern => pattern.test(text));
};

/**
 * Safely truncates text for preview
 * @param {string} text - The text to truncate
 * @param {number} maxLength - Maximum length before truncation
 * @returns {string} - Truncated text
 */
export const truncateText = (text, maxLength = 100) => {
  if (!text || typeof text !== 'string') {
    return '';
  }
  
  if (text.length <= maxLength) {
    return text;
  }
  
  return text.substring(0, maxLength).trim() + '...';
};

/**
 * Extracts the first few lines for preview
 * @param {string} text - The text to extract from
 * @param {number} maxLines - Maximum number of lines to extract
 * @returns {string} - First few lines of text
 */
export const extractPreview = (text, maxLines = 3) => {
  if (!text || typeof text !== 'string') {
    return '';
  }
  
  const lines = text.split('\n').filter(line => line.trim());
  const previewLines = lines.slice(0, maxLines);
  
  if (lines.length > maxLines) {
    previewLines.push('...');
  }
  
  return previewLines.join('\n');
};
