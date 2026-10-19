#!/bin/sh
# Runs on the OpenWrt node, from install-openwrt.sh, with the shipped dir as $1:
# bin/, openwrt/, update-hosts.sh and node/{config.yaml,wgmesh.uci,wgmesh.hosts}.
set -eu
d=$1

"$d/bin/stunmesh-bb" stunmesh-avahi -h >/dev/null 2>&1 || {
	echo "bin/stunmesh-bb does not run here; wrong arch bundle?" >&2
	exit 1
}
# The DHT proxies need TLS 1.3. The store plugin prefers curl, but curl on
# OpenWrt 22.03 (mbedTLS 2.28) can't do it; there remove curl and the plugin
# falls back to wget (uclient-fetch), which can.
for cmd in wg avahi-browse base64; do
	command -v $cmd >/dev/null || {
		echo "missing $cmd; install wireguard-tools avahi-dbus-daemon avahi-utils coreutils-base64 (apk or opkg)" >&2
		exit 1
	}
done
command -v curl >/dev/null || command -v wget >/dev/null || {
	echo "missing curl or wget" >&2
	exit 1
}

mkdir -p /usr/local/bin /etc/stunmesh /etc/wireguard
chmod 700 /etc/stunmesh /etc/wireguard
for f in stunmesh-bb stunmesh-opendht-shell; do
	cp "$d/bin/$f" /usr/local/bin/$f
	chmod 755 /usr/local/bin/$f
done
ln -sf stunmesh-bb /usr/local/bin/stunmesh-go
ln -sf stunmesh-bb /usr/local/bin/stunmesh-avahi
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
