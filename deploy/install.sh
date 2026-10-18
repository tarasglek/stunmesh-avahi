#!/usr/bin/env bash
# Install the stunmesh WireGuard mesh on this systemd node from this bundle:
# binaries, the node's wgmesh/stunmesh configs from CONFIG_DIR (rendered by
# gen.py), and the systemd unit.
#   sudo ./install.sh CONFIG_DIR [NODE]    # NODE defaults to the short hostname
set -euo pipefail

BUNDLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${EUID:-$(id -u)}" -ne 0 ] || [ $# -lt 1 ]; then
	echo "usage: sudo $0 CONFIG_DIR [NODE]" >&2
	exit 1
fi
CONFIG_DIR=$1
NODE=${2:-$(hostname -s)}
SRC="$CONFIG_DIR/$NODE"
if [ ! -f "$SRC/wgmesh.conf" ]; then
	echo "no wgmesh.conf for node '$NODE' in $CONFIG_DIR; run gen.py first" >&2
	exit 1
fi
"$BUNDLE/bin/stunmesh-bb" stunmesh-avahi -h >/dev/null 2>&1 || {
	echo "bin/stunmesh-bb does not run here; wrong arch bundle?" >&2
	exit 1
}
for cmd in wg wg-quick avahi-browse curl base64; do
	command -v $cmd >/dev/null || {
		echo "missing $cmd; apt install wireguard-tools avahi-daemon avahi-utils curl coreutils" >&2
		exit 1
	}
done

# install_if_changed SRC DST MODE: install and print DST when contents differ
install_if_changed() {
	if ! cmp -s "$1" "$2"; then
		install -D -m "$3" "$1" "$2"
		echo "$2"
	fi
}

bin_changed=$(install_if_changed "$BUNDLE/bin/stunmesh-bb" /usr/local/bin/stunmesh-bb 0755)
bin_changed+=$(install_if_changed "$BUNDLE/bin/stunmesh-opendht-shell" /usr/local/bin/stunmesh-opendht-shell 0755)
ln -sfn stunmesh-bb /usr/local/bin/stunmesh-go
ln -sfn stunmesh-bb /usr/local/bin/stunmesh-avahi

install -d -m 0700 /etc/wireguard /etc/stunmesh
if [ ! -s /etc/wireguard/wgmesh.key ]; then
	(umask 077 && wg genkey > /etc/wireguard/wgmesh.key)
	echo "generated /etc/wireguard/wgmesh.key, public key: $(wg pubkey < /etc/wireguard/wgmesh.key)"
	echo "add it to mesh.yaml and reinstall the other nodes before they can reach this one"
fi

wg_changed=$(install_if_changed "$SRC/wgmesh.conf" /etc/wireguard/wgmesh.conf 0600)
sm_changed=$(install_if_changed "$SRC/config.yaml" /etc/stunmesh/config.yaml 0600)
unit_changed=$(install_if_changed "$BUNDLE/systemd/stunmesh-wgmesh.service" \
	/etc/systemd/system/stunmesh-wgmesh.service 0644)

"$BUNDLE/update-hosts.sh" "$CONFIG_DIR/wgmesh.hosts"

[ -z "$unit_changed" ] || systemctl daemon-reload
systemctl enable -q wg-quick@wgmesh stunmesh-wgmesh

# stunmesh-wgmesh is bound to wg-quick@wgmesh, so restarting the interface
# restarts stunmesh too; stunmesh reads its config only at startup.
if [ -n "$wg_changed" ]; then
	systemctl restart wg-quick@wgmesh
	systemctl start stunmesh-wgmesh
elif [ -n "$sm_changed$unit_changed$bin_changed" ]; then
	systemctl restart stunmesh-wgmesh
else
	systemctl start wg-quick@wgmesh stunmesh-wgmesh
fi
echo "$NODE: wg-quick@wgmesh $(systemctl is-active wg-quick@wgmesh), stunmesh-wgmesh $(systemctl is-active stunmesh-wgmesh)"
