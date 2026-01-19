import React from 'react';
import { X, Clock, User, Shield } from 'lucide-react';
import TokenDisplay from './TokenDisplay';

const AuthTokensDialog = ({ isOpen, onClose, keycloak }) => {
  if (!isOpen) return null;

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A';
    return new Date(timestamp * 1000).toLocaleString();
  };

  const getTokenInfo = () => {
    if (!keycloak || !keycloak.tokenParsed) return {};
    
    const token = keycloak.tokenParsed;
    return {
      expires: token.exp,
      issued: token.iat,
      subject: token.sub,
      realm: keycloak.realm,
      issuer: token.iss,
      audience: token.aud
    };
  };

  const tokenInfo = getTokenInfo();

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <div className="flex items-center space-x-3">
            <Shield className="h-6 w-6 text-blue-600" />
            <h2 className="text-xl font-semibold text-gray-900">Authentication Tokens</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded-full p-1"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Token Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center space-x-2">
              <Clock className="h-4 w-4 text-gray-500" />
              <span className="text-sm text-gray-600">Expires:</span>
              <span className="text-sm font-medium">{formatDate(tokenInfo.expires)}</span>
            </div>
            <div className="flex items-center space-x-2">
              <Clock className="h-4 w-4 text-gray-500" />
              <span className="text-sm text-gray-600">Issued:</span>
              <span className="text-sm font-medium">{formatDate(tokenInfo.issued)}</span>
            </div>
            <div className="flex items-center space-x-2">
              <User className="h-4 w-4 text-gray-500" />
              <span className="text-sm text-gray-600">Subject:</span>
              <span className="text-sm font-medium">{tokenInfo.subject || 'N/A'}</span>
            </div>
            <div className="flex items-center space-x-2">
              <Shield className="h-4 w-4 text-gray-500" />
              <span className="text-sm text-gray-600">Realm:</span>
              <span className="text-sm font-medium">{tokenInfo.realm || 'N/A'}</span>
            </div>
          </div>

          {/* Access Token */}
          <TokenDisplay
            label="Access Token"
            token={keycloak?.token || 'No token available'}
            type="access"
          />

          {/* ID Token */}
          <TokenDisplay
            label="ID Token"
            token={keycloak?.idToken || 'No ID token available'}
            type="id"
          />

          {/* Additional Info */}
          {keycloak?.refreshToken && (
            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-700">
                Refresh Token
              </label>
              <div className="text-xs text-gray-500 bg-gray-50 p-3 rounded border">
                <strong>Note:</strong> Refresh tokens are sensitive credentials used to obtain new access tokens. 
                They are automatically managed by the application and should not be shared.
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end p-6 border-t border-gray-200">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default AuthTokensDialog;
