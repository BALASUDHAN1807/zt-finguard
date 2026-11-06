#!/usr/bin/env bash
# Build every ZT-FinGuard image for x86-64 AND ARM64 and push it to Docker Hub.
#
#   docker login                                  # once, with a Docker Hub access token
#   IMAGE_PREFIX=bala1807/zt-finguard- ./scripts/push-images.sh
#   (or: make push IMAGE_PREFIX=bala1807/zt-finguard-)
#
# Result: bala1807/zt-finguard-gateway:latest, ...-auth, ...-account, ... (8 images),
# each also tagged with today's date so you can roll back.
# Images contain no secrets: certificates, keys and passwords are mounted at run time.
set -euo pipefail
cd "$(dirname "$0")/.."

PREFIX="${IMAGE_PREFIX:?set IMAGE_PREFIX, e.g. IMAGE_PREFIX=bala1807/zt-finguard-}"
TAG="${IMAGE_TAG:-latest}"
DATE_TAG="$(date +%Y%m%d)"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
SERVICES=(gateway dashboard auth account transaction risk audit responder)

command -v docker >/dev/null || { echo "docker not installed"; exit 1; }
docker buildx version >/dev/null 2>&1 || { echo "docker buildx plugin missing"; exit 1; }

# Multi-platform builds need a BuildKit builder (docker-container driver).
if ! docker buildx inspect zt-builder >/dev/null 2>&1; then
  docker buildx create --name zt-builder --driver docker-container >/dev/null
fi
docker buildx use zt-builder

echo "Pushing ${#SERVICES[@]} images as ${PREFIX}<service>:${TAG} for ${PLATFORMS}"
for svc in "${SERVICES[@]}"; do
  echo "==> ${PREFIX}${svc}"
  docker buildx build \
    --platform "$PLATFORMS" \
    -f services/Containerfile --build-arg SERVICE="$svc" \
    --label org.opencontainers.image.source="https://hub.docker.com/r/${PREFIX%/*}" \
    -t "${PREFIX}${svc}:${TAG}" -t "${PREFIX}${svc}:${DATE_TAG}" \
    --push services/
  # Cosign: sign the pushed image in the registry (by digest). Needs the cosign CLI; the key is the same
  # ECDSA P-256 key the local deployment uses, so `cosign verify --key ${SECRETS_DIR:-secrets}/cosign.pub <image>` works.
  if command -v cosign >/dev/null 2>&1 && [[ -f ${SECRETS_DIR:-secrets}/cosign.key ]]; then
    digest=$(docker buildx imagetools inspect "${PREFIX}${svc}:${TAG}" --format '{{json .Manifest.Digest}}' | tr -d '"')
    [[ -f ${SECRETS_DIR:-secrets}/cosign-import.key ]] || COSIGN_PASSWORD="" cosign import-key-pair --key ${SECRETS_DIR:-secrets}/cosign.key \
      --output-key-prefix ${SECRETS_DIR:-secrets}/cosign-import >/dev/null
    COSIGN_PASSWORD="" cosign sign --yes --key ${SECRETS_DIR:-secrets}/cosign-import.key "${PREFIX}${svc}@${digest}" \
      && echo "    cosign signed ${PREFIX}${svc}@${digest}"
  fi
done

cat <<EOF

Done. On the server put this in zt-finguard/.env and deploy without building:
  IMAGE_PREFIX=${PREFIX}
  ./deploy.sh --pull            (or, on a fresh cloud VM: IMAGE_PREFIX=${PREFIX} ./deploy/cloud-setup.sh)
EOF
