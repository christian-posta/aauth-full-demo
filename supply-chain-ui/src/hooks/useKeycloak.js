import { useState, useEffect, useCallback } from 'react';
import { keycloak, keycloakInitOptions } from '../keycloak';

export const useKeycloak = () => {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [error, setError] = useState(null);
  const [isInitialized, setIsInitialized] = useState(false);

  const loadUserProfile = useCallback(async () => {
    try {
      console.log('Loading user profile...');
      
      // First try to get user info from the token itself
      const tokenParsed = keycloak.tokenParsed;
      console.log('Token parsed data:', tokenParsed);
      
      let userData = {
        id: keycloak.subject,
        username: tokenParsed?.preferred_username || tokenParsed?.sub,
        email: tokenParsed?.email,
        firstName: tokenParsed?.given_name,
        lastName: tokenParsed?.family_name,
        fullName: `${tokenParsed?.given_name || ''} ${tokenParsed?.family_name || ''}`.trim(),
        roles: tokenParsed?.realm_access?.roles || []
      };
      
      // If we don't have enough info from token, try userinfo endpoint
      if (!userData.username || !userData.email) {
        try {
          console.log('Fetching additional user info from userinfo endpoint...');
          const userInfoUrl = `${keycloak.authServerUrl}/realms/${keycloak.realm}/protocol/openid-connect/userinfo`;
          const response = await fetch(userInfoUrl, {
            headers: {
              'Authorization': `Bearer ${keycloak.token}`
            }
          });
          
          if (response.ok) {
            const userInfo = await response.json();
            console.log('User info from endpoint:', userInfo);
            
            // Merge with token data, preferring userinfo endpoint data
            userData = {
              ...userData,
              username: userInfo.preferred_username || userData.username,
              email: userInfo.email || userData.email,
              firstName: userInfo.given_name || userData.firstName,
              lastName: userInfo.family_name || userData.lastName,
              fullName: `${userInfo.given_name || userData.firstName || ''} ${userInfo.family_name || userData.lastName || ''}`.trim()
            };
          } else {
            console.warn('Failed to fetch user info from endpoint, using token data only');
          }
        } catch (fetchError) {
          console.warn('Error fetching user info from endpoint:', fetchError);
          console.log('Using token data only');
        }
      }
      
      console.log('Final processed user data:', userData);
      setUser(userData);
      setIsLoading(false);
    } catch (error) {
      console.error('Failed to load user profile:', error);
      setError('Failed to load user profile');
      setIsLoading(false);
    }
  }, []);

  // Initialize Keycloak
  useEffect(() => {
    // Prevent multiple initializations
    if (isInitialized) {
      console.log('Keycloak already initialized, skipping...');
      return;
    }

    // Check if Keycloak instance is already initialized
    if (keycloak.authenticated !== undefined) {
      console.log('Keycloak instance already initialized, checking authentication...');
      setIsInitialized(true);
      setIsAuthenticated(keycloak.authenticated);
      
      if (keycloak.authenticated) {
        loadUserProfile();
      } else {
        setIsLoading(false);
      }
      return;
    }

    console.log('Initializing Keycloak...');
    setIsInitialized(true);
    
    keycloak.init(keycloakInitOptions)
      .then((authenticated) => {
        console.log('Keycloak initialized, authenticated:', authenticated);
        setIsAuthenticated(authenticated);
        
        if (authenticated) {
          loadUserProfile();
        } else {
          setIsLoading(false);
        }
      })
      .catch((error) => {
        console.error('Keycloak initialization failed:', error);
        setError('Failed to initialize authentication');
        setIsLoading(false);
        setIsInitialized(false); // Reset flag on error
      });
  }, [loadUserProfile, isInitialized]);

  const login = useCallback(() => {
    console.log('Initiating Keycloak login...');
    setError(null);
    keycloak.login();
  }, []);

  const logout = useCallback(() => {
    console.log('Initiating Keycloak logout...');
    keycloak.logout();
  }, []);

  const refreshToken = useCallback(async () => {
    try {
      console.log('Refreshing token...');
      const refreshed = await keycloak.updateToken(70);
      console.log('Token refresh result:', refreshed);
      return refreshed;
    } catch (error) {
      console.error('Token refresh failed:', error);
      return false;
    }
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  // Debug logging for state changes
  useEffect(() => {
    console.log('Keycloak state changed:', { user, isLoading, isAuthenticated, error });
  }, [user, isLoading, isAuthenticated, error]);

  return {
    user,
    isLoading,
    isAuthenticated,
    error,
    login,
    logout,
    refreshToken,
    clearError,
    keycloak
  };
};
