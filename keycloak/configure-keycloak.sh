#!/bin/bash
# Create a Keycloak realm and OAuth clients via Admin REST API (idempotent)

BASE_URL="${1:-http://localhost:8080}"
REALM_NAME="${2:-aauth-test}"
ADMIN_USER="${3:-admin}"
ADMIN_PASSWORD="${4:-admin}"

# Track results for final summary
CREATED=()
ALREADY_EXISTED=()

echo "Configuring Keycloak at $BASE_URL (realm: $REALM_NAME)..."
echo ""

# Get admin token
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASSWORD" \
  -d "grant_type=password" \
  -d "client_id=admin-cli")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
  echo ""
  echo "❌ ERROR: Failed to get admin token."
  echo ""
  echo "Possible causes:"
  echo "  1. Admin user doesn't exist yet (first-time setup)"
  echo "  2. Wrong credentials"
  echo "  3. Keycloak not fully started"
  echo ""
  echo "Solutions:"
  echo "  Option 1: Create admin user via web UI (first time only):"
  echo "    1. Open http://localhost:8080 in your browser"
  echo "    2. Fill in the form to create the admin user"
  echo "    3. Then run this script again"
  echo ""
  echo "  Option 2: Start Keycloak with bootstrap admin (recommended):"
  echo "    java -jar quarkus/server/target/lib/quarkus-run.jar start-dev \\"
  echo "      --bootstrap-admin-username=admin \\"
  echo "      --bootstrap-admin-password=admin"
  echo ""
  echo "  Option 3: Use admin client credentials (if configured):"
  echo "    ./scripts/create_realm.sh $BASE_URL $REALM_NAME <client-id> <client-secret>"
  echo ""
  echo "Token response: $TOKEN_RESPONSE"
  exit 1
fi

# Create realm
REALM_JSON="{\"realm\":\"$REALM_NAME\",\"enabled\":true}"

CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/admin/realms" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$REALM_JSON")

HTTP_CODE=$(echo "$CREATE_RESPONSE" | tail -n1)
BODY=$(echo "$CREATE_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "204" ]; then
  CREATED+=("Realm '$REALM_NAME'")
elif [ "$HTTP_CODE" = "409" ]; then
  ALREADY_EXISTED+=("Realm '$REALM_NAME'")
else
  echo "❌ ERROR: Failed to create realm. HTTP $HTTP_CODE"
  echo "Response: $BODY"
  exit 1
fi

# Create supply-chain-ui OAuth client (idempotent)
CLIENT_ID="supply-chain-ui"
CLIENT_CHECK=$(curl -s -w "\n%{http_code}" "$BASE_URL/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

CLIENT_CHECK_HTTP=$(echo "$CLIENT_CHECK" | tail -n1)
CLIENT_CHECK_BODY=$(echo "$CLIENT_CHECK" | sed '$d')

if echo "$CLIENT_CHECK_BODY" | grep -q '"clientId"' 2>/dev/null; then
  ALREADY_EXISTED+=("OAuth client '$CLIENT_ID'")
else
  CLIENT_JSON=$(cat <<EOF
{
  "clientId": "$CLIENT_ID",
  "enabled": true,
  "publicClient": true,
  "redirectUris": ["http://localhost:3050/*"],
  "webOrigins": ["http://localhost:3050"],
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true
}
EOF
)

  CLIENT_CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/admin/realms/$REALM_NAME/clients" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$CLIENT_JSON")

  CLIENT_HTTP=$(echo "$CLIENT_CREATE_RESPONSE" | tail -n1)
  CLIENT_BODY=$(echo "$CLIENT_CREATE_RESPONSE" | sed '$d')

  if [ "$CLIENT_HTTP" = "201" ] || [ "$CLIENT_HTTP" = "204" ]; then
    CREATED+=("OAuth client '$CLIENT_ID'")
  elif [ "$CLIENT_HTTP" = "409" ]; then
    ALREADY_EXISTED+=("OAuth client '$CLIENT_ID'")
  else
    echo "❌ ERROR: Failed to create OAuth client '$CLIENT_ID'. HTTP $CLIENT_HTTP"
    echo "Response: $CLIENT_BODY"
    exit 1
  fi
fi

# Create test user mcp-user (idempotent)
TEST_USER="mcp-user"
USER_CHECK=$(curl -s "$BASE_URL/admin/realms/$REALM_NAME/users?username=$TEST_USER" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

if echo "$USER_CHECK" | grep -q '"username"' 2>/dev/null; then
  ALREADY_EXISTED+=("User '$TEST_USER'")
else
  USER_JSON=$(cat <<EOF
{
  "username": "$TEST_USER",
  "firstName": "mcp",
  "lastName": "user",
  "email": "mcp@user.com",
  "emailVerified": true,
  "enabled": true
}
EOF
)

  USER_CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" -D - -X POST "$BASE_URL/admin/realms/$REALM_NAME/users" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$USER_JSON")

  USER_HTTP=$(echo "$USER_CREATE_RESPONSE" | tail -n1)
  USER_BODY=$(echo "$USER_CREATE_RESPONSE" | sed '$d')

  if [ "$USER_HTTP" = "201" ]; then
    USER_ID=$(echo "$USER_CREATE_RESPONSE" | grep -i "Location:" | sed 's|.*/users/||' | tr -d '\r\n')
    if [ -n "$USER_ID" ]; then
      PWD_JSON="{\"type\":\"password\",\"value\":\"user123\",\"temporary\":false}"
      PWD_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$BASE_URL/admin/realms/$REALM_NAME/users/$USER_ID/reset-password" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$PWD_JSON")
      PWD_HTTP=$(echo "$PWD_RESPONSE" | tail -n1)
      if [ "$PWD_HTTP" = "204" ]; then
        CREATED+=("User '$TEST_USER' (mcp@user.com / user123)")
      else
        echo "❌ ERROR: Failed to set password for user '$TEST_USER'. HTTP $PWD_HTTP"
        exit 1
      fi
    else
      echo "❌ ERROR: Could not get user ID from create response"
      exit 1
    fi
  elif [ "$USER_HTTP" = "409" ]; then
    ALREADY_EXISTED+=("User '$TEST_USER'")
  else
    echo "❌ ERROR: Failed to create user '$TEST_USER'. HTTP $USER_HTTP"
    echo "Response: $USER_BODY"
    exit 1
  fi
fi

# Final summary
echo ""
echo "--- Summary ---"
if [ ${#CREATED[@]} -gt 0 ]; then
  for item in "${CREATED[@]}"; do
    echo "✅ Created: $item"
  done
fi
if [ ${#ALREADY_EXISTED[@]} -gt 0 ]; then
  for item in "${ALREADY_EXISTED[@]}"; do
    echo "ℹ️  Already exists: $item"
  done
fi
echo ""
echo "Done."

