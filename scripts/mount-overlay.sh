#!/bin/bash
# Mount a directory as overlay while preserving existing sub-overlays
# Usage: mount-overlay.sh <path>
# Example: mount-overlay.sh /etc
#          mount-overlay.sh /usr

set -e

TARGET_PATH="${1:-/etc}"
TARGET_NAME="${TARGET_PATH#/}"
TARGET_NAME="${TARGET_NAME//\//-}"

OVERLAY_UPPER="/var/volatile/overlay/${TARGET_NAME}-root/upper"
OVERLAY_WORK="/var/volatile/overlay/${TARGET_NAME}-root/work"
MOUNT_INFO_FILE="/tmp/${TARGET_NAME}-overlay-mounts.txt"

# Check if target is already an overlay
if mount | grep -q "^overlay on ${TARGET_PATH} "; then
    echo "${TARGET_PATH} is already an overlay"
    exit 0
fi

# Save existing sub-mounts info to file
echo "Saving existing ${TARGET_PATH}/* overlay mounts..."
mount | grep "on ${TARGET_PATH}/" > "$MOUNT_INFO_FILE" || true
cat "$MOUNT_INFO_FILE"

# Get mount points sorted by depth (deepest first for unmount)
MOUNTS_TO_UNMOUNT=$(awk '{print $3}' "$MOUNT_INFO_FILE" | awk '{print length, $0}' | sort -rn | cut -d' ' -f2-)

# Unmount all sub-mounts
echo "Unmounting..."
for mnt in $MOUNTS_TO_UNMOUNT; do
    echo "  umount $mnt"
    umount "$mnt" 2>/dev/null || true
done

# Mount overlay
echo "Mounting ${TARGET_PATH} overlay..."
mkdir -p "$OVERLAY_UPPER" "$OVERLAY_WORK"
mount -t overlay overlay -o "lowerdir=${TARGET_PATH},upperdir=$OVERLAY_UPPER,workdir=$OVERLAY_WORK" "${TARGET_PATH}"

# Remount previous mounts (shallowest first)
echo "Remounting previous mounts..."
MOUNTS_TO_REMOUNT=$(awk '{print $3}' "$MOUNT_INFO_FILE" | awk '{print length, $0}' | sort -n | cut -d' ' -f2-)
for mnt in $MOUNTS_TO_REMOUNT; do
    line=$(grep "on $mnt " "$MOUNT_INFO_FILE")
    type=$(echo "$line" | awk '{print $5}')
    opts=$(echo "$line" | sed 's/.*(\(.*\))/\1/')

    echo "  mount -t $type ... -o $opts $mnt"
    mount -t "$type" "$type" -o "$opts" "$mnt" 2>/dev/null || echo "    skipped or failed"
done

rm -f "$MOUNT_INFO_FILE"

echo ""
echo "Done. Current ${TARGET_PATH} mounts:"
mount | grep "${TARGET_PATH}"
