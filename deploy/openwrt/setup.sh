#!/bin/sh
# Runs on the OpenWrt node, from install-openwrt.sh, with the shipped dir as $1:
# bin/, openwrt/, update-hosts.sh and node/{config.yaml,wgmesh.uci,wgmesh.hosts}.
set -eu
d=$1
# Installed over the mesh, the ssh session rides on wgmesh, which ifup below
# recreates; if the session drops, finish the install anyway.
trap '' HUP PIPE

"$d/bin/stunmesh-go" -version >/dev/null 2>&1 || {
	echo "bin/stunmesh-go does not run here; wrong arch bundle?" >&2
	exit 1
}
for cmd in wg avahi-browse; do
	command -v $cmd >/dev/null || {
		echo "missing $cmd; install wireguard-tools avahi-dbus-daemon avahi-utils (apk or opkg)" >&2
		exit 1
	}
done

mkdir -p /usr/local/bin /etc/stunmesh /etc/wireguard
chmod 700 /etc/stunmesh /etc/wireguard
# Bundles up to v0.2 shipped a makebb binary behind a stunmesh-go symlink,
# which cp would write through; remove it all first. The old daemon's shell
# plugin calls fail until the restart below.
rm -f /usr/local/bin/stunmesh-bb /usr/local/bin/stunmesh-avahi /usr/local/bin/stunmesh-opendht-shell /usr/local/bin/stunmesh-go
cp "$d/bin/stunmesh-go" /usr/local/bin/stunmesh-go
chmod 755 /usr/local/bin/stunmesh-go
cp "$d/node/config.yaml" /etc/stunmesh/config.yaml
chmod 600 /etc/stunmesh/config.yaml
cp "$d/openwrt/stunmesh.init" /etc/init.d/stunmesh
chmod 755 /etc/init.d/stunmesh

if [ ! -s /etc/wireguard/wgmesh.key ]; then
	(umask 077 && wg genkey >/etc/wireguard/wgmesh.key)
	echo "generated /etc/wireguard/wgmesh.key; add the public key below to mesh.yaml and reinstall the other nodes"
fi
uci -q batch <"$d/node/wgmesh.uci" || true # deletes of absent options fail harmlessly
uci set network.wgmesh.private_key="$(cat /etc/wireguard/wgmesh.key)"
uci commit network
uci commit firewall
ifup wgmesh
/etc/init.d/firewall reload >/dev/null 2>&1

# dnsmasq serves the mesh names to this node's LAN too.
sh "$d/update-hosts.sh" "$d/node/wgmesh.hosts"
/etc/init.d/dnsmasq reload

/etc/init.d/stunmesh enable
/etc/init.d/stunmesh running && /etc/init.d/stunmesh restart || /etc/init.d/stunmesh start
rm -rf "$d"
echo "$(uci get system.@system[0].hostname): wgmesh $(wg pubkey </etc/wireguard/wgmesh.key), stunmesh $(/etc/init.d/stunmesh running && echo running || echo stopped)"
