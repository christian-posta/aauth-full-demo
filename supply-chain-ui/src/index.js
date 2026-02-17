import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

// Persist AAuth return params before any redirect (e.g. Keycloak check-sso) can strip them.
// This runs synchronously BEFORE React mounts, so it captures the URL params immediately.
console.log('[index.js] ====== PAGE LOAD ======');
console.log('[index.js] Timestamp:', new Date().toISOString());
console.log('[index.js] Full URL:', window.location.href);

const params = new URLSearchParams(window.location.search);
console.log('[index.js] URL search:', window.location.search);
console.log('[index.js] aauth_authorized:', params.get('aauth_authorized'));
console.log('[index.js] request_id:', params.get('request_id'));
console.log('[index.js] aauth_error:', params.get('aauth_error'));
console.log('[index.js] code:', params.get('code'));
console.log('[index.js] state:', params.get('state'));

// Fallback: If Keycloak redirected to the frontend with code and state (wrong redirect_uri),
// forward to the backend callback so it can exchange the code.
const codeParam = params.get('code');
const stateParam = params.get('state');
if (codeParam && stateParam) {
  const backendBase = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000';
  const callbackUrl = `${backendBase.replace(/\/$/, '')}/auth/aauth/callback?${window.location.search}`;
  console.log('[index.js] 🔀 Keycloak sent code+state to frontend; forwarding to backend:', callbackUrl);
  window.location.replace(callbackUrl);
  // Don't render React - we're navigating away
} else {

// Check existing sessionStorage state
console.log('[index.js] Existing sessionStorage state:');
console.log('[index.js]   - aauth_return_request_id:', sessionStorage.getItem('aauth_return_request_id'));
console.log('[index.js]   - aauth_return_pending:', sessionStorage.getItem('aauth_return_pending'));
console.log('[index.js]   - aauth_error:', sessionStorage.getItem('aauth_error'));

if (params.get('aauth_authorized') === '1' && params.get('request_id')) {
  const rid = params.get('request_id');
  console.log('[index.js] 🔑 Saving request_id to sessionStorage:', rid);
  sessionStorage.setItem('aauth_return_request_id', rid);
  // Also set a flag to indicate we're returning from consent
  sessionStorage.setItem('aauth_return_pending', 'true');
  console.log('[index.js] ✅ sessionStorage updated');
} else if (params.get('aauth_error') === '1') {
  // Persist AAuth error so UI can display it (Keycloak check-sso may strip URL params)
  const err = params.get('error') || 'unknown';
  const desc = params.get('error_description') || 'Unknown error';
  const rid = params.get('request_id') || '';
  console.log('[index.js] ⚠️ Saving AAuth error to sessionStorage:', err, desc);
  sessionStorage.setItem('aauth_error', err);
  sessionStorage.setItem('aauth_error_description', desc);
  sessionStorage.setItem('aauth_error_request_id', rid);
  console.log('[index.js] ✅ sessionStorage updated');
} else {
  console.log('[index.js] No aauth_authorized=1 or aauth_error params found in URL');
}

console.log('[index.js] Final sessionStorage state:');
console.log('[index.js]   - aauth_return_request_id:', sessionStorage.getItem('aauth_return_request_id'));
console.log('[index.js]   - aauth_return_pending:', sessionStorage.getItem('aauth_return_pending'));
console.log('[index.js]   - aauth_error:', sessionStorage.getItem('aauth_error'));
console.log('[index.js] ====== END PAGE LOAD SETUP ======');

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
}