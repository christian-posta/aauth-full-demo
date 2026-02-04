#!/bin/bash
# Set AAuth consent-required scopes and scope prefixes via Admin REST API
# Run interactively to configure scopes/prefixes, or use env vars for non-interactive mode.

BASE_URL="${1:-http://localhost:8080}"
REALM_NAME="${2:-aauth-test}"
ADMIN_USER="${3:-admin}"
ADMIN_PASSWORD="${4:-admin}"

# Default consent-required scopes (matches current hardcoded behavior)
DEFAULT_CONSENT_SCOPES='["openid","profile","email"]'
DEFAULT_CONSENT_PREFIXES='["user.","profile.","email."]'

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
  local type="$1"           # "scopes" or "prefixes"
  local examples="$2"       # e.g. "openid, profile, email" or "user., profile., email."
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

# Display current scopes/prefixes from realm JSON
view_current() {
  local realm_json="$1"
  if command -v jq >/dev/null 2>&1; then
    local scopes prefixes
    scopes=$(echo "$realm_json" | jq -r '.attributes["aauth.consent.required.scopes"] // "[]"')
    prefixes=$(echo "$realm_json" | jq -r '.attributes["aauth.consent.required.scope.prefixes"] // "[]"')
    echo ""
    echo "Current values in Keycloak realm '$REALM_NAME':"
    echo "  aauth.consent.required.scopes:         $scopes"
    echo "  aauth.consent.required.scope.prefixes: $prefixes"
    if [ "$scopes" = "[]" ] && [ "$prefixes" = "[]" ]; then
      echo ""
      echo "  (Both are empty - no consent-required scopes/prefixes configured)"
    fi
    echo ""
  else
    echo ""
    echo "⚠️  jq required to view current values. Install with: brew install jq"
    echo ""
  fi
}

# Main interactive configuration - returns action: "apply", "view", "clear", or "quit"
# When action is "apply" or "clear", CONSENT_SCOPES and CONSENT_PREFIXES are set
run_interactive_menu() {
  local realm_json="$1"

  while true; do
    echo ""
    echo "What would you like to do?"
    echo "  1) Scopes only   - configure exact scope names (e.g. openid, profile, email)"
    echo "  2) Prefixes only - configure scope prefixes (e.g. user., profile., email.)"
    echo "  3) Both scopes and prefixes"
    echo "  4) Use defaults for both"
    echo "  5) View current scopes/prefixes"
    echo "  6) Clear scopes and prefixes (set to empty)"
    echo "  7) Quit (no changes)"
    echo ""
    read -r -p "Choice [1-7]: " choice

    case "$choice" in
      5)
        view_current "$realm_json"
        read -r -p "Press Enter to continue..."
        continue
        ;;
      6)
        CONSENT_SCOPES='[]'
        CONSENT_PREFIXES='[]'
        echo ""
        echo "Will clear both scopes and prefixes (set to empty arrays)."
        read -r -p "Apply to Keycloak? [Y/n]: " confirm
        if [[ "$confirm" =~ ^[nN] ]]; then
          echo "Cancelled."
          continue
        fi
        APPLY_NOW=1
        return
        ;;
      7)
        echo "Quitting without changes."
        exit 0
        ;;
    esac

    local do_scopes=0
    local do_prefixes=0

    case "$choice" in
      1) do_scopes=1 ;;
      2) do_prefixes=1 ;;
      3) do_scopes=1; do_prefixes=1 ;;
      4)
        CONSENT_SCOPES="$DEFAULT_CONSENT_SCOPES"
        CONSENT_PREFIXES="$DEFAULT_CONSENT_PREFIXES"
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
      CONSENT_SCOPES=$(prompt_for_list "scopes" "openid, profile, email" \
        "$DEFAULT_CONSENT_SCOPES" "$DEFAULT_CONSENT_SCOPES")
    else
      CONSENT_SCOPES="$DEFAULT_CONSENT_SCOPES"
    fi

    if [ $do_prefixes -eq 1 ]; then
      CONSENT_PREFIXES=$(prompt_for_list "prefixes" "user., profile., email." \
        "$DEFAULT_CONSENT_PREFIXES" "$DEFAULT_CONSENT_PREFIXES")
    else
      CONSENT_PREFIXES="$DEFAULT_CONSENT_PREFIXES"
    fi

    echo ""
    echo "Summary:"
    echo "  Scopes:   $CONSENT_SCOPES"
    echo "  Prefixes: $CONSENT_PREFIXES"
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

# Use env vars if both set (non-interactive); otherwise we'll connect first and run interactive menu
if [ -n "${AAUTH_CONSENT_SCOPES}" ] && [ -n "${AAUTH_CONSENT_PREFIXES}" ]; then
  CONSENT_SCOPES="$AAUTH_CONSENT_SCOPES"
  CONSENT_PREFIXES="$AAUTH_CONSENT_PREFIXES"
  echo "Using values from environment (AAUTH_CONSENT_SCOPES, AAUTH_CONSENT_PREFIXES)"
  echo "  Scopes:   $CONSENT_SCOPES"
  echo "  Prefixes: $CONSENT_PREFIXES"
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

# Interactive mode: run menu (View, Clear, Configure, Quit)
if [ -z "${AAUTH_CONSENT_SCOPES}" ] || [ -z "${AAUTH_CONSENT_PREFIXES}" ]; then
  APPLY_NOW=0
  run_interactive_menu "$REALM_JSON"
  # If we get here, user chose Apply or Clear; CONSENT_SCOPES and CONSENT_PREFIXES are set
fi

echo ""
echo "Applying to Keycloak..."

# Validate and normalize: ensure values are pure JSON arrays (no stray text)
if command -v jq >/dev/null 2>&1; then
  if ! CONSENT_SCOPES=$(echo "$CONSENT_SCOPES" | jq -c '.' 2>/dev/null) || [ -z "$CONSENT_SCOPES" ]; then
    echo "❌ ERROR: Invalid JSON for scopes: $CONSENT_SCOPES"
    exit 1
  fi
  if ! CONSENT_PREFIXES=$(echo "$CONSENT_PREFIXES" | jq -c '.' 2>/dev/null) || [ -z "$CONSENT_PREFIXES" ]; then
    echo "❌ ERROR: Invalid JSON for prefixes: $CONSENT_PREFIXES"
    exit 1
  fi
fi

# Check if jq is available for JSON manipulation
if command -v jq >/dev/null 2>&1; then
  # Use jq to merge attributes
  UPDATED_REALM_JSON=$(echo "$REALM_JSON" | jq --arg scopes "$CONSENT_SCOPES" --arg prefixes "$CONSENT_PREFIXES" '
    .attributes = (.attributes // {}) |
    .attributes["aauth.consent.required.scopes"] = $scopes |
    .attributes["aauth.consent.required.scope.prefixes"] = $prefixes
  ')

  if [ $? -ne 0 ]; then
    echo "❌ ERROR: Failed to update realm JSON with jq"
    exit 1
  fi
else
  # Fallback: Use sed/awk to merge attributes (simpler but less robust)
  echo "⚠️  Warning: jq not found. Using basic JSON manipulation (may fail with complex realm configs)."
  echo "   Install jq for better reliability: brew install jq (macOS) or apt-get install jq (Linux)"
  echo ""

  # Create a temporary file for the realm JSON
  TEMP_REALM=$(mktemp)
  echo "$REALM_JSON" > "$TEMP_REALM"

  # Try to merge attributes using sed
  ESCAPED_SCOPES=$(echo "$CONSENT_SCOPES" | sed 's/[[\]/\\&/g')
  ESCAPED_PREFIXES=$(echo "$CONSENT_PREFIXES" | sed 's/[[\]/\\&/g')

  # Check if attributes section exists
  if grep -q '"attributes"' "$TEMP_REALM"; then
    sed -i.bak "s/\"attributes\":{[^}]*}/\"attributes\":{\"aauth.consent.required.scopes\":$ESCAPED_SCOPES,\"aauth.consent.required.scope.prefixes\":$ESCAPED_PREFIXES}/" "$TEMP_REALM" 2>/dev/null
    if [ $? -ne 0 ]; then
      echo "❌ ERROR: Failed to update attributes with sed. Please install jq for better JSON support."
      rm -f "$TEMP_REALM" "$TEMP_REALM.bak"
      exit 1
    fi
  else
    sed -i.bak "s/}$/,\"attributes\":{\"aauth.consent.required.scopes\":$ESCAPED_SCOPES,\"aauth.consent.required.scope.prefixes\":$ESCAPED_PREFIXES}}/" "$TEMP_REALM" 2>/dev/null
    if [ $? -ne 0 ]; then
      echo "❌ ERROR: Failed to add attributes with sed. Please install jq for better JSON support."
      rm -f "$TEMP_REALM" "$TEMP_REALM.bak"
      exit 1
    fi
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
  if [ "$CONSENT_SCOPES" = "[]" ] && [ "$CONSENT_PREFIXES" = "[]" ]; then
    echo "✅ Successfully cleared AAuth consent scopes and prefixes for realm '$REALM_NAME'!"
  else
    echo "✅ Successfully set AAuth consent attributes for realm '$REALM_NAME'!"
  fi
  echo ""
  echo "Configured values:"
  echo "  aauth.consent.required.scopes:         $CONSENT_SCOPES"
  echo "  aauth.consent.required.scope.prefixes: $CONSENT_PREFIXES"
  echo ""
  echo "Non-interactive usage:"
  echo "  export AAUTH_CONSENT_SCOPES='[\"openid\",\"profile\",\"email\"]'"
  echo "  export AAUTH_CONSENT_PREFIXES='[\"user.\",\"profile.\",\"email.\"]'"
  echo "  $0 $BASE_URL $REALM_NAME $ADMIN_USER $ADMIN_PASSWORD"
else
  echo "❌ ERROR: Failed to update realm. HTTP $HTTP_CODE"
  echo "Response: $BODY"
  exit 1
fi
