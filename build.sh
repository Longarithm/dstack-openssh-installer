#!/bin/bash

set -e

IMAGE_NAME="${1:-kvin/dstack-openssh-installer}"
IMAGE_TAG="${2:-latest}"

echo "=========================================="
echo "Building OpenSSH Server Installer"
echo "=========================================="

cd "$(dirname "$0")"

echo "Build context: $(pwd)"
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"

echo "Checking required files..."
for file in scripts/install-openssh.sh docker/Dockerfile; do
    if [[ ! -f "$file" ]]; then
        echo "Missing required file: $file"
        exit 1
    fi
done

echo "Building Docker image..."
docker build --progress=plain -f docker/Dockerfile -t "${IMAGE_NAME}:${IMAGE_TAG}" .

echo
echo "=========================================="
echo "Build Complete!"
echo "=========================================="
echo
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo
echo "Usage:"
echo
echo "Single-command installation (with SSH public key):"
echo "  docker run --rm --privileged --pid=host --net=host -v /:/host \\"
echo "    -e SSH_PUBKEY=\"ssh-ed25519 AAAA... user@host\" \\"
echo "    ${IMAGE_NAME}:${IMAGE_TAG}"
echo
echo "Interactive installation:"
echo "  docker run -it --rm --privileged --pid=host --net=host -v /:/host \\"
echo "    ${IMAGE_NAME}:${IMAGE_TAG} bash"
echo
echo "Check build info:"
echo "  docker run --rm ${IMAGE_NAME}:${IMAGE_TAG} cat /usr/local/share/BUILD_INFO"
echo
