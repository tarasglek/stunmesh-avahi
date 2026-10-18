#!/usr/bin/env bash
# Install the stunmesh WireGuard mesh on an OpenWrt node over ssh from this
# bundle: binaries, the node's config.yaml and wgmesh.uci from CONFIG_DIR
# (rendered by gen.py), a procd service. Runs on any host; use the bundle
# matching the node's arch.
#   ./install-openwrt.sh CONFIG_DIR NODE [SSH_TARGET]    # target defaults to root@NODE
set -euo pipefail

BUNDLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR=${1:?usage: $0 CONFIG_DIR NODE [SSH_TARGET]}
NODE=${2:?usage: $0 CONFIG_DIR NODE [SSH_TARGET]}
TARGET=${3:-root@$NODE}
SRC="$CONFIG_DIR/$NODE"
[ -f "$SRC/wgmesh.uci" ] || { echo "no OpenWrt config for '$NODE' in $CONFIG_DIR; run gen.py first" >&2; exit 1; }

# Ship only what the node needs: binaries, OpenWrt scripts, its own config.
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp -a "$BUNDLE/bin" "$BUNDLE/openwrt" "$BUNDLE/update-hosts.sh" "$stage/"
mkdir "$stage/node"
cp "$SRC/config.yaml" "$SRC/wgmesh.uci" "$CONFIG_DIR/wgmesh.hosts" "$stage/node/"

tar -C "$stage" -cf - . | ssh "$TARGET" 'd=$(mktemp -d) && tar -C "$d" -xf - && sh "$d/openwrt/setup.sh" "$d"'
