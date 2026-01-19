import Keycloak from 'keycloak-js';

// Keycloak configuration with environment variable support
const keycloakConfig = {
  url: process.env.REACT_APP_KEYCLOAK_URL || 'http://localhost:8080',
  realm: process.env.REACT_APP_KEYCLOAK_REALM || 'mcp-realm',
  clientId: process.env.REACT_APP_KEYCLOAK_CLIENT_ID || 'supply-chain-ui'
};

console.log('Keycloak config:', keycloakConfig);

export const keycloak = new Keycloak(keycloakConfig);

// Keycloak initialization options
export const keycloakInitOptions = {
  onLoad: 'check-sso',
  silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html',
  checkLoginIframe: false,
  pkceMethod: 'S256'
};
