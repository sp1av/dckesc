#!/bin/bash

# Configuration
HOST="$HOSTIP_SPLAV"
CONTROL_ID="$CONTROL_SPLAV"
IMAGES="$IMAGES_SPLAV"

# Set Trivy cache directory to a writable location
export TRIVY_CACHE_DIR="/tmp/trivy-cache"
mkdir -p "$TRIVY_CACHE_DIR"
chmod 777 "$TRIVY_CACHE_DIR"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required commands
if ! command_exists trivy; then
    echo "Error: trivy is not installed. Please install it first."
    exit 1
fi

# Function to scan a single image
scan_image() {
    local image=$1
    local registry=$2
    local username=$3
    local password=$4
    local tls_verify=$5

    echo "Scanning image: $image"

    # Build trivy command
    local trivy_cmd="trivy image"

    # Add registry if specified
    if [ -n "$registry" ]; then
        trivy_cmd="$trivy_cmd --registry $registry"
    fi

    # Add authentication if provided
    if [ -n "$username" ] && [ -n "$password" ]; then
        trivy_cmd="$trivy_cmd --username $username --password $password"
    fi

    # Add TLS verification option
    if [ "$tls_verify" = "false" ]; then
        trivy_cmd="$trivy_cmd --insecure"
    fi

    # Add image and output format
    trivy_cmd="$trivy_cmd --format json $image"

    # Execute scan
    local scan_result
    scan_result=$(eval "$trivy_cmd" 2>&1)
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo "Error scanning image $image: $scan_result"
        return 1
    fi

    # Send results to server
    local response
    response=$(curl -s -X POST "http://$HOST:2517/scan/image/result" \
        -H "Content-Type: application/json" \
        -d "{
            \"uuid\": \"$CONTROL_ID\",
            \"image\": \"$image\",
            \"scan_data\": $scan_result
        }")

    if [ $? -ne 0 ]; then
        echo "Error sending results for image $image"
        return 1
    fi

    echo "Successfully scanned and sent results for image: $image"
    return 0
}

# Main script
echo "Starting image scan process..."
echo "Control ID: $CONTROL_ID"
echo "Images to scan: $IMAGES"

# Parse images and scan each one
for image in $IMAGES; do
    # Extract registry and image name
    if [[ $image == *"/"* ]]; then
        registry=$(echo "$image" | cut -d'/' -f1)
        image_name=$(echo "$image" | cut -d'/' -f2-)
    else
        registry=""
        image_name=$image
    fi

    # Prompt for registry credentials if needed
    if [ -n "$registry" ]; then
        read -p "Enter username for registry $registry (leave empty if not needed): " username
        if [ -n "$username" ]; then
            read -s -p "Enter password: " password
            echo
        else
            password=""
        fi

        read -p "Disable TLS verification for $registry? (y/n): " disable_tls
        if [ "$disable_tls" = "y" ]; then
            tls_verify="false"
        else
            tls_verify="true"
        fi
    else
        username=""
        password=""
        tls_verify="true"
    fi

    # Scan the image
    scan_image "$image" "$registry" "$username" "$password" "$tls_verify"
done

# Clean up cache directory
rm -rf "$TRIVY_CACHE_DIR"

echo "Scan process completed." 