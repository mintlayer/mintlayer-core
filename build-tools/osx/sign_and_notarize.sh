#!/bin/bash

set -e
set -o nounset

ARCH=$1
VERSION=$2

# Configuration
APP_NAME="Mintlayer Node GUI"
DMG_NAME="Mintlayer_Node_GUI_macos_${VERSION}_${ARCH}.dmg"
KEYCHAIN_NAME="build.keychain"
KEYCHAIN_PASSWORD="temporary_password"
NOTARIZATION_TIMEOUT=60 # Maximum wait time for notarization in seconds

# Function to display usage information
usage() {
    echo "Usage: $0 <architecture> <version>"
    echo "  architecture: aarch64 or x86_64"
    echo "  version: in the format x.y.z"
    echo
    echo "Environment variables (can be set in .env file):"
    echo "  MACOS_CERTIFICATE_BASE64: Base64 encoded certificate"
    echo "  MACOS_CERTIFICATE_PASSWORD: Certificate password"
    echo "  MACOS_CERTIFICATE_NAME: Certificate name for signing"
    echo "  APPLE_ID: Apple ID for notarization"
    echo "  APPLE_TEAM_ID: Apple Team ID for notarization"
    echo "  APPLE_ID_PASSWORD: App-specific password for Apple ID"
    exit 1
}

# Function to check required environment variables
check_env_vars() {
    local required_vars=(
        "MACOS_CERTIFICATE_BASE64"
        "MACOS_CERTIFICATE_PASSWORD"
        "MACOS_CERTIFICATE_NAME"
        "APPLE_ID"
        "APPLE_TEAM_ID"
        "APPLE_ID_PASSWORD"
    )

    for var in "${required_vars[@]}"; do
        if [ -z "${!var+x}" ]; then
            echo "Error: $var is not set. Please set it in your environment or .env file."
            exit 1
        fi
    done
}

# Function to ensure create-dmg is installed
ensure_create_dmg_is_installed() {
    if ! command -v create-dmg &> /dev/null; then
        echo "create-dmg not found. Installing..."
        brew install create-dmg
    else
        echo "create-dmg is already installed."
    fi
}

# Function to create app bundle
create_app_bundle() {
    echo "Creating app bundle..."
    local bundle_path="target/release/bundle/${ARCH}/${APP_NAME}.app"
    mkdir -p "${bundle_path}/Contents/"{MacOS,Resources}
    cp "target/${ARCH}-apple-darwin/release/node-gui" "${bundle_path}/Contents/MacOS/"
    cp "build-tools/assets/logo.icns" "${bundle_path}/Contents/Resources/"

    echo "Generating Info.plist..."
    local version
    version=$(cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "node-gui") | .version')
    if [ -z "${version+x}" ]; then
        echo "Error: Failed to retrieve version from cargo metadata"
        exit 1
    fi
    local build_number=$(date +%Y%m%d.%H%M%S)
    sed -e "s/VERSION_PLACEHOLDER/$version/g" \
        -e "s/BUILD_PLACEHOLDER/$build_number/g" \
        -e "s/MACOS_VERSION_PLACEHOLDER/10.13/g" \
        "build-tools/osx/Info.plist.template" > "${bundle_path}/Contents/Info.plist"
}

# Function to set up keychain and import certificate
setup_keychain() {
    echo "Setting up keychain and importing certificate..."
    local certificate_path="$RUNNER_TEMP/build_certificate.p12"
    local keychain_path="$RUNNER_TEMP/$KEYCHAIN_NAME"
    local apple_cert_path="build-tools/osx/DeveloperIDG2CA.cer"
    echo "$MACOS_CERTIFICATE_BASE64" | base64 --decode > "$certificate_path"
    security create-keychain -p "$KEYCHAIN_PASSWORD" "$keychain_path"
    security set-keychain-settings -lut 21600 "$keychain_path"
    security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$keychain_path"
    security import "$apple_cert_path" -k "$keychain_path" -T /usr/bin/codesign
    security import "$certificate_path" -k "$keychain_path" -P "$MACOS_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
    security list-keychains -d user -s "$keychain_path"
    security default-keychain -s "$keychain_path"
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$keychain_path"
}

# Function to sign the app
sign_app() {
    echo "Signing the app..."
    /usr/bin/codesign --force -s "$MACOS_CERTIFICATE_NAME" \
        --options runtime \
        --entitlements "build-tools/osx/entitlements.plist" \
        --timestamp "target/release/bundle/${ARCH}/${APP_NAME}.app" -v
}

# Function to create and sign DMG
create_and_sign_dmg() {
    echo "Creating DMG..."
    create-dmg \
      --volname "$APP_NAME" \
      --window-pos 200 120 \
      --window-size 600 400 \
      --icon-size 100 \
      --icon "${APP_NAME}.app" 175 120 \
      --hide-extension "${APP_NAME}.app" \
      --app-drop-link 425 120 \
      $DMG_NAME \
      "target/release/bundle/${ARCH}/"

    echo "Signing the DMG..."
    /usr/bin/codesign --force -s "$MACOS_CERTIFICATE_NAME" \
        --options runtime \
        --timestamp $DMG_NAME -v
}

# Function to notarize and staple
notarize_and_staple() {
    echo "Notarizing the DMG..."
    local notarization_output
    notarization_output=$(xcrun notarytool submit $DMG_NAME \
        --apple-id "$APPLE_ID" \
        --team-id "$APPLE_TEAM_ID" \
        --password "$APPLE_ID_PASSWORD" \
        --wait --timeout $NOTARIZATION_TIMEOUT)

    echo "Notarization output:"
    echo "$notarization_output"

    local submission_id
    submission_id=$(echo "$notarization_output" | grep "id:" | head -n 1 | awk '{print $2}')

    if [ -z "${submission_id+x}" ]; then
        echo "Failed to extract submission ID. Notarization may have failed."
        exit 1
    fi

    echo "Notarization submitted with ID: $submission_id"

    local start_time=$(date +%s)
    while true; do
        local status_output
        status_output=$(xcrun notarytool info "$submission_id" \
            --apple-id "$APPLE_ID" \
            --team-id "$APPLE_TEAM_ID" \
            --password "$APPLE_ID_PASSWORD")

        echo "Notarization status output:"
        echo "$status_output"

        local status
        status=$(echo "$status_output" | grep "status:" | awk '{print $2}')

        if [ -z "${status+x}" ]; then
            echo "Error: Failed to extract status from notarization info"
            exit 1
        fi

        echo "Notarization status: $status"

        if [ "$status" == "Accepted" ]; then
            echo "Notarization successful!"
            break
        elif [ "$status" == "Invalid" ]; then
            echo "Notarization failed!"
            exit 1
        fi

        local current_time=$(date +%s)
        if [ $((current_time - start_time)) -ge $NOTARIZATION_TIMEOUT ]; then
            echo "Notarization timed out after $NOTARIZATION_TIMEOUT seconds"
            exit 1
        fi

        sleep 10
    done

    echo "Stapling the notarization ticket..."
    xcrun stapler staple $DMG_NAME

    echo "Verifying notarization..."
    spctl -a -vv -t install $DMG_NAME
}

# Function to clean up
cleanup() {
    echo "Cleaning up..."
    security delete-keychain "$RUNNER_TEMP/$KEYCHAIN_NAME"
    rm "$RUNNER_TEMP/build_certificate.p12"
    if [ -z "${RUNNER_TEMP_PRESERVE+x}" ]; then
        rm -rf "$RUNNER_TEMP"
    fi
}

# Main execution
main() {
    if [ $# -ne 2 ]; then
        usage
    fi

    if [ "$ARCH" != "aarch64" ] && [ "$ARCH" != "x86_64" ]; then
        echo "Invalid architecture. Use aarch64 or x86_64."
        exit 1
    fi

    if [ -f .env ]; then
        set -a
        source .env
        set +a
    fi

    # Set RUNNER_TEMP to a local temporary directory if it's not already set
    if [ -z "${RUNNER_TEMP+x}" ]; then
        RUNNER_TEMP=$(mktemp -d)
        echo "RUNNER_TEMP is not set. Using temporary directory: $RUNNER_TEMP"
    fi

    check_env_vars
    ensure_create_dmg_is_installed
    create_app_bundle
    setup_keychain
    sign_app
    create_and_sign_dmg
    notarize_and_staple
    cleanup

    echo "Process completed successfully!"
}

main "$@"