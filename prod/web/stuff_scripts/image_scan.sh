#!/bin/bash

# Configuration
HOST="$HOSTIP_SPLAV"
REGISTRY_NAMES=($CONTROL_SPLAV)
IMAGES=($IMAGES_SPLAV)
OWNER="$OWNER_SPLAV"

scan_image() {
    local image=$1
    local registry_name=$2

    echo "Scanning image: $image"

    sudo docker commit $image 127.0.0.1:5000/$registry_name > /dev/null # tmp solution
    # push image to registry 
    sudo docker push  127.0.0.1:5000/$registry_name > /dev/null # tmp solution


    local response
    response=$(curl -s -X POST "http://$HOST:1703/api/image-scan/create" \
        -d "registry=registry:5000" \
        -d "registry_name=$registry_name" \
        -d "image=$image" \
        -d "owner=$OWNER")

    if [ $? -ne 0 ]; then
        echo "Error sending results for image $image"
        return 1
    fi

    echo "Successfully scanned and sent results for image: $image"
    return 0
}

echo "Starting image scan process..."
echo "Images to scan: $IMAGES"

counter=0
for i in "${!IMAGES[@]}"; do
    registry_name=${REGISTRY_NAMES[$counter]}
    image=${IMAGES[$counter]}

    scan_image "$image" "$registry_name"
    counter=$((counter + 1))
done

echo "Scan process completed." 