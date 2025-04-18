#!/bin/bash

# Configuration
HOST="$HOSTIP_SPLAV"
CONTROL_ID="$CONTROL_SPLAV"
IMAGES="$IMAGES_SPLAV"
OWNER="$OWNER_SPLAV"

scan_image() {
    local image=$1
    local host=$2
    local registry_name=$3

    echo "Scanning image: $image"

    # commit image
    docker commit $image $host:5000/$registry_name
    # push image to registry 
    docker push  $host:5000/$registry_name


    local response
    response=$(curl -s -X POST "http://$host:1703/api/image-scan/create" \
        -d "")

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


echo "Scan process completed." 