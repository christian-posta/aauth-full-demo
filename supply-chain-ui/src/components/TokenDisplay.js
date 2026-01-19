import React, { useState } from 'react';
import { Copy, Eye, EyeOff, Check } from 'lucide-react';

const TokenDisplay = ({ label, token, type = 'access' }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy token:', err);
    }
  };

  const toggleVisibility = () => {
    setIsVisible(!isVisible);
  };

  const displayToken = isVisible ? token : '•'.repeat(50);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="block text-sm font-medium text-gray-700">
          {label}
        </label>
        <div className="flex space-x-2">
          <button
            onClick={toggleVisibility}
            className="inline-flex items-center px-2 py-1 text-xs font-medium text-gray-600 hover:text-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded"
            title={isVisible ? 'Hide token' : 'Show token'}
          >
            {isVisible ? (
              <EyeOff className="h-4 w-4" />
            ) : (
              <Eye className="h-4 w-4" />
            )}
          </button>
          <button
            onClick={handleCopy}
            className="inline-flex items-center px-2 py-1 text-xs font-medium text-gray-600 hover:text-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded"
            title="Copy token"
          >
            {copied ? (
              <Check className="h-4 w-4 text-green-600" />
            ) : (
              <Copy className="h-4 w-4" />
            )}
          </button>
        </div>
      </div>
      <div className="relative">
        <textarea
          readOnly
          value={displayToken}
          className="w-full px-3 py-2 text-xs font-mono bg-gray-50 border border-gray-300 rounded-md resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          rows={type === 'id' ? 8 : 4}
          style={{ fontFamily: 'monospace' }}
        />
      </div>
    </div>
  );
};

export default TokenDisplay;
