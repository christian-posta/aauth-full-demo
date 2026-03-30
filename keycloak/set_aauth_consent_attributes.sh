#!/bin/bash
# Set AAuth consent-required scopes, scope prefixes, and clarification scopes via Admin REST API
# Run interactively to configure, or use env vars for non-interactive mode.

BASE_URL="${1:-http://localhost:8080}"
REALM_NAME="${2:-aauth-test}"
ADMIN_USER="${3:-admin}"
ADMIN_PASSWORD="${4:-admin}"

# Default values
DEFAULT_CONSENT_SCOPES='["openid","profile","email"]'
DEFAULT_CONSENT_PREFIXES='["user.","profile.","email."]'
DEFAULT_CLARIFICATION_SCOPES='[]'

# Convert comma-separated input to JSON array (e.g. "openid, profile, email" -> ["openid","profile","email"])
to_json_array() {
  local input="$1"
  if command -v jq >/dev/null 2>&1; then
    echo "$input" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$";"")) | map(select(length>0))'
  else
    # Fallback: simple bash loop
    local result="["
    local first=1
    IFS=',' read -ra parts <<< "$input"
    for part in "${parts[@]}"; do
      part=$(echo "$part" | xargs)
      [ -z "$part" ] && continue
      [ $first -eq 0 ] && result+=","
      result+="\"$part\""
      first=0
    done
    result+="]"
    echo "$result"
  fi
}

# Interactive prompt for a list (scopes or prefixes)
# Writes prompts to stderr so only the JSON result goes to stdout (for capture)
prompt_for_list() {
  local type="$1"           # label shown to user
  local examples="$2"       # e.g. "openid, profile, email"
  local default_json="$3"
  local default_display="$4"

  echo "" >&2
  echo "--- Configure $type ---" >&2
  echo "  Examples: $examples" >&2
  echo "  Default:  $default_display" >&2
  echo "" >&2
  read -r -p "Enter $type (comma-separated, or press Enter for default): " user_input

  if [ -z "$user_input" ]; then
    printf '%s' "$default_json"
  else
    to_json_array "$user_input" | tr -d '\n'
  fi
}

# Display current values from realm JSON
view_current() {
  local realm_json="$1"
  if command -v jq >/dev/null 2>&1; then
    local scopes prefixes clarification
    scopes=$(echo "$realm_json" | jq -r '.attributes["aauth.consent.required.scopes"] // "[]"')
    prefixes=$(echo "$realm_json" | jq -r '.attributes["aauth.consent.required.scope.prefixes"] // "[]"')
    clarification=$(echo "$realm_json" | jq -r '.attributes["aauth.clarification.required.scopes"] // "[]"')
    echo ""
    echo "Current values in Keycloak realm '$REALM_NAME':"
    echo "  aauth.consent.required.scopes:         $scopes"
    echo "  aauth.consent.required.scope.prefixes: $prefixes"
    echo "  aauth.clarification.required.scopes:   $clarification"
    echo ""
  else
    echo ""
    echo "⚠️  jq required to view current values. Install with: brew install jq"
    echo ""
  fi
}

# Main interactive menu
run_interactive_menu() {
  local realm_json="$1"

  while true; do
    echo ""
    echo "What would you like to configure?"
    echo "  1) Consent scopes only   - exact scope names that require user consent"
    echo "     (e.g. openid, profile, email)"
    echo "  2) Consent prefixes only - scope name prefixes that require user consent"
    echo "     (e.g. user., profile., email.)"
    echo "  3) Clarification scopes  - scopes that trigger the clarification chat UI"
    echo "     (e.g. clarify.read, sensitive.data)"
    echo "  4) All three"
    echo "  5) Use defaults (consent: openid/profile/email + user./profile./email. prefixes;"
    echo "     clarification: empty)"
    echo "  6) View current values"
    echo "  7) Clear all (set everything to empty arrays)"
    echo "  8) Quit (no changes)"
    echo ""
    read -r -p "Choice [1-8]: " choice

    case "$choice" in
      6)
        view_current "$realm_json"
        read -r -p "Press Enter to continue..."
        continue
        ;;
      7)
        CONSENT_SCOPES='[]'
        CONSENT_PREFIXES='[]'
        CLARIFICATION_SCOPES='[]'
        echo ""
        echo "Will clear consent scopes, prefixes, and clarification scopes."
        read -r -p "Apply to Keycloak? [Y/n]: " confirm
        if [[ "$confirm" =~ ^[nN] ]]; then
          echo "Cancelled."
          continue
        fi
        APPLY_NOW=1
        return
        ;;
      8)
        echo "Quitting without changes."
        exit 0
        ;;
    esac

    local do_scopes=0
    local do_prefixes=0
    local do_clarification=0

    case "$choice" in
      1) do_scopes=1 ;;
      2) do_prefixes=1 ;;
      3) do_clarification=1 ;;
      4) do_scopes=1; do_prefixes=1; do_clarification=1 ;;
      5)
        CONSENT_SCOPES="$DEFAULT_CONSENT_SCOPES"
        CONSENT_PREFIXES="$DEFAULT_CONSENT_PREFIXES"
        CLARIFICATION_SCOPES="$DEFAULT_CLARIFICATION_SCOPES"
        echo ""
        echo "Using defaults. Proceeding to Keycloak..."
        APPLY_NOW=1
        return
        ;;
      *)
        echo "Invalid choice. Try again."
        continue
        ;;
    esac

    if [ $do_scopes -eq 1 ]; then
      CONSENT_SCOPES=$(prompt_for_list "consent scopes" "openid, profile, email" \
        "$DEFAULT_CONSENT_SCOPES" "$DEFAULT_CONSENT_SCOPES")
    else
      CONSENT_SCOPES="${CONSENT_SCOPES:-$DEFAULT_CONSENT_SCOPES}"
    fi

    if [ $do_prefixes -eq 1 ]; then
      CONSENT_PREFIXES=$(prompt_for_list "consent prefixes" "user., profile., email." \
        "$DEFAULT_CONSENT_PREFIXES" "$DEFAULT_CONSENT_PREFIXES")
    else
      CONSENT_PREFIXES="${CONSENT_PREFIXES:-$DEFAULT_CONSENT_PREFIXES}"
    fi

    if [ $do_clarification -eq 1 ]; then
      CLARIFICATION_SCOPES=$(prompt_for_list "clarification scopes" \
        "clarify.read, clarify.write, sensitive.data" \
        "$DEFAULT_CLARIFICATION_SCOPES" "(empty - disabled)")
    else
      CLARIFICATION_SCOPES="${CLARIFICATION_SCOPES:-$DEFAULT_CLARIFICATION_SCOPES}"
    fi

    echo ""
    echo "Summary:"
    echo "  aauth.consent.required.scopes:         $CONSENT_SCOPES"
    echo "  aauth.consent.required.scope.prefixes: $CONSENT_PREFIXES"
    echo "  aauth.clarification.required.scopes:   $CLARIFICATION_SCOPES"
    echo ""
    read -r -p "Apply these to Keycloak? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[nN] ]]; then
      echo "Cancelled."
      continue
    fi
    APPLY_NOW=1
    return
  done
}

# --- Start ---
echo "=============================================="
echo "  AAuth Consent Attributes Configuration"
echo "=============================================="
echo ""
echo "Keycloak: $BASE_URL"
echo "Realm:    $REALM_NAME"
echo ""

# Use env vars if all three are set (non-interactive mode)
if [ -n "${AAUTH_CONSENT_SCOPES}" ] && [ -n "${AAUTH_CONSENT_PREFIXES}" ] && [ -n "${AAUTH_CLARIFICATION_SCOPES+x}" ]; then
  CONSENT_SCOPES="$AAUTH_CONSENT_SCOPES"
  CONSENT_PREFIXES="$AAUTH_CONSENT_PREFIXES"
  CLARIFICATION_SCOPES="${AAUTH_CLARIFICATION_SCOPES:-[]}"
  echo "Using values from environment variables"
  echo "  aauth.consent.required.scopes:         $CONSENT_SCOPES"
  echo "  aauth.consent.required.scope.prefixes: $CONSENT_PREFIXES"
  echo "  aauth.clarification.required.scopes:   $CLARIFICATION_SCOPES"
  echo ""
fi

echo "Connecting to Keycloak..."

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
  echo "    1. Open $BASE_URL in your browser"
  echo "    2. Fill in the form to create the admin user"
  echo "    3. Then run this script again"
  echo ""
  echo "  Option 2: Start Keycloak with bootstrap admin (recommended):"
  echo "    java -jar quarkus/server/target/lib/quarkus-run.jar start-dev \\"
  echo "      --bootstrap-admin-username=$ADMIN_USER \\"
  echo "      --bootstrap-admin-password=$ADMIN_PASSWORD"
  echo ""
  echo "Token response: $TOKEN_RESPONSE"
  exit 1
fi

# Get current realm
REALM_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/admin/realms/$REALM_NAME" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json")

HTTP_CODE=$(echo "$REALM_RESPONSE" | tail -n1)
REALM_JSON=$(echo "$REALM_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
  echo "❌ ERROR: Failed to get realm '$REALM_NAME'. HTTP $HTTP_CODE"
  echo "Response: $REALM_JSON"
  echo ""
  echo "Make sure the realm exists. You can create it with:"
  echo "  ./scripts/create_realm.sh $BASE_URL $REALM_NAME"
  exit 1
fi

# Interactive mode if env vars not fully provided
if [ -z "${CONSENT_SCOPES}" ] || [ -z "${CONSENT_PREFIXES}" ]; then
  APPLY_NOW=0
  run_interactive_menu "$REALM_JSON"
fi

echo ""
echo "Applying to Keycloak..."

# Validate: ensure values are pure JSON arrays
if command -v jq >/dev/null 2>&1; then
  if ! CONSENT_SCOPES=$(echo "$CONSENT_SCOPES" | jq -c '.' 2>/dev/null) || [ -z "$CONSENT_SCOPES" ]; then
    echo "❌ ERROR: Invalid JSON for consent scopes: $CONSENT_SCOPES"
    exit 1
  fi
  if ! CONSENT_PREFIXES=$(echo "$CONSENT_PREFIXES" | jq -c '.' 2>/dev/null) || [ -z "$CONSENT_PREFIXES" ]; then
    echo "❌ ERROR: Invalid JSON for consent prefixes: $CONSENT_PREFIXES"
    exit 1
  fi
  CLARIFICATION_SCOPES="${CLARIFICATION_SCOPES:-[]}"
  if ! CLARIFICATION_SCOPES=$(echo "$CLARIFICATION_SCOPES" | jq -c '.' 2>/dev/null) || [ -z "$CLARIFICATION_SCOPES" ]; then
    echo "❌ ERROR: Invalid JSON for clarification scopes: $CLARIFICATION_SCOPES"
    exit 1
  fi
fi

CLARIFICATION_SCOPES="${CLARIFICATION_SCOPES:-[]}"

# Merge attributes into realm JSON
if command -v jq >/dev/null 2>&1; then
  UPDATED_REALM_JSON=$(echo "$REALM_JSON" | jq \
    --arg scopes "$CONSENT_SCOPES" \
    --arg prefixes "$CONSENT_PREFIXES" \
    --arg clarification "$CLARIFICATION_SCOPES" '
    .attributes = (.attributes // {}) |
    .attributes["aauth.consent.required.scopes"] = $scopes |
    .attributes["aauth.consent.required.scope.prefixes"] = $prefixes |
    .attributes["aauth.clarification.required.scopes"] = $clarification
  ')

  if [ $? -ne 0 ]; then
    echo "❌ ERROR: Failed to update realm JSON with jq"
    exit 1
  fi
else
  echo "⚠️  Warning: jq not found. Using basic JSON manipulation (may fail with complex realm configs)."
  echo "   Install jq for better reliability: brew install jq (macOS) or apt-get install jq (Linux)"
  echo ""

  TEMP_REALM=$(mktemp)
  echo "$REALM_JSON" > "$TEMP_REALM"

  ESCAPED_SCOPES=$(echo "$CONSENT_SCOPES" | sed 's/[[\]/\\&/g')
  ESCAPED_PREFIXES=$(echo "$CONSENT_PREFIXES" | sed 's/[[\]/\\&/g')
  ESCAPED_CLARIFICATION=$(echo "$CLARIFICATION_SCOPES" | sed 's/[[\]/\\&/g')

  if grep -q '"attributes"' "$TEMP_REALM"; then
    sed -i.bak "s/\"attributes\":{[^}]*}/\"attributes\":{\"aauth.consent.required.scopes\":$ESCAPED_SCOPES,\"aauth.consent.required.scope.prefixes\":$ESCAPED_PREFIXES,\"aauth.clarification.required.scopes\":$ESCAPED_CLARIFICATION}/" "$TEMP_REALM" 2>/dev/null
  else
    sed -i.bak "s/}$/,\"attributes\":{\"aauth.consent.required.scopes\":$ESCAPED_SCOPES,\"aauth.consent.required.scope.prefixes\":$ESCAPED_PREFIXES,\"aauth.clarification.required.scopes\":$ESCAPED_CLARIFICATION}}/" "$TEMP_REALM" 2>/dev/null
  fi

  if [ $? -ne 0 ]; then
    echo "❌ ERROR: Failed to update attributes with sed. Please install jq for better JSON support."
    rm -f "$TEMP_REALM" "$TEMP_REALM.bak"
    exit 1
  fi

  UPDATED_REALM_JSON=$(cat "$TEMP_REALM")
  rm -f "$TEMP_REALM" "$TEMP_REALM.bak"
fi

# Update realm
UPDATE_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$BASE_URL/admin/realms/$REALM_NAME" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$UPDATED_REALM_JSON")

HTTP_CODE=$(echo "$UPDATE_RESPONSE" | tail -n1)
BODY=$(echo "$UPDATE_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "204" ] || [ "$HTTP_CODE" = "200" ]; then
  if [ "$CONSENT_SCOPES" = "[]" ] && [ "$CONSENT_PREFIXES" = "[]" ] && [ "$CLARIFICATION_SCOPES" = "[]" ]; then
    echo "✅ Successfully cleared all AAuth scope attributes for realm '$REALM_NAME'!"
  else
    echo "✅ Successfully set AAuth scope attributes for realm '$REALM_NAME'!"
  fi
  echo ""
  echo "Configured values:"
  echo "  aauth.consent.required.scopes:         $CONSENT_SCOPES"
  echo "  aauth.consent.required.scope.prefixes: $CONSENT_PREFIXES"
  echo "  aauth.clarification.required.scopes:   $CLARIFICATION_SCOPES"
  echo ""
  echo "Non-interactive usage:"
  echo "  export AAUTH_CONSENT_SCOPES='[\"openid\",\"profile\",\"email\"]'"
  echo "  export AAUTH_CONSENT_PREFIXES='[\"user.\",\"profile.\",\"email.\"]'"
  echo "  export AAUTH_CLARIFICATION_SCOPES='[\"clarify.read\",\"clarify.write\"]'"
  echo "  $0 $BASE_URL $REALM_NAME $ADMIN_USER $ADMIN_PASSWORD"
else
  echo "❌ ERROR: Failed to update realm. HTTP $HTTP_CODE"
  echo "Response: $BODY"
  exit 1
fi
