import React, { useState, useRef, useEffect } from 'react';
import { ChevronDown, User, Settings, Shield, LogOut } from 'lucide-react';
import AuthTokensDialog from './AuthTokensDialog';

const UserDropdown = ({ user, onLogout, keycloak }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [showAuthDialog, setShowAuthDialog] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogout = () => {
    setIsOpen(false);
    onLogout();
  };

  const openAuthDialog = () => {
    setIsOpen(false);
    setShowAuthDialog(true);
  };

  return (
    <>
      <div className="relative" ref={dropdownRef}>
        {/* User Button */}
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-100 rounded-md transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
        >
          <div className="flex items-center space-x-2">
            <User className="h-5 w-5 text-gray-400" />
            <span>{user.fullName || user.username}</span>
          </div>
          <ChevronDown className={`h-4 w-4 text-gray-400 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
        </button>

        {/* Dropdown Menu */}
        {isOpen && (
          <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg ring-1 ring-black ring-opacity-5 z-50">
            <div className="py-1">
              {/* Profile Option */}
              <button
                onClick={() => setIsOpen(false)}
                className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 focus:outline-none focus:bg-gray-100"
              >
                <User className="h-4 w-4 mr-3 text-gray-400" />
                Profile
              </button>

              {/* Settings Option */}
              <button
                onClick={() => setIsOpen(false)}
                className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 focus:outline-none focus:bg-gray-100"
              >
                <Settings className="h-4 w-4 mr-3 text-gray-400" />
                Settings
              </button>

              {/* Auth Tokens Option */}
              <button
                onClick={openAuthDialog}
                className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 focus:outline-none focus:bg-gray-100"
              >
                <Shield className="h-4 w-4 mr-3 text-gray-400" />
                Auth Tokens
              </button>

              {/* Divider */}
              <div className="border-t border-gray-100 my-1"></div>

              {/* Logout Option */}
              <button
                onClick={handleLogout}
                className="flex items-center w-full px-4 py-2 text-sm text-red-700 hover:bg-red-50 focus:outline-none focus:bg-red-50"
              >
                <LogOut className="h-4 w-4 mr-3 text-red-400" />
                Sign Out
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Auth Tokens Dialog */}
      <AuthTokensDialog
        isOpen={showAuthDialog}
        onClose={() => setShowAuthDialog(false)}
        keycloak={keycloak}
      />
    </>
  );
};

export default UserDropdown;
