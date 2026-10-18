# stunmesh bundle

Everything to run a [stunmesh-go](https://github.com/tjjh89017/stunmesh-go)
WireGuard mesh with [stunmesh-avahi](https://github.com/tarasglek/stunmesh-avahi)
LAN discovery on systemd and OpenWrt nodes. Nodes find each other's public UDP
endpoint with STUN and OpenDHT (no account needed); nodes sharing a public IP
use LAN addresses found over mDNS.

- `bin/stunmesh-bb`: stunmesh-go and stunmesh-avahi in one binary, called through the `stunmesh-go` and `stunmesh-avahi` symlinks
- `bin/stunmesh-opendht-shell`: OpenDHT store plugin
- `gen.py`: renders each node's configs from `mesh.yaml` (needs [uv](https://docs.astral.sh/uv/))
- `install.sh`: installs a systemd node, run on the node
- `install-openwrt.sh`: installs an OpenWrt node over ssh, run from any host
- `licenses/`: stunmesh-go and stunmesh-avahi licenses

Every node listens on UDP 51830 and gets `<node>.mesh.internal` in `/etc/hosts`.

## Use

Keep your mesh in a private directory, e.g. `~/mesh`:

```sh
mkdir ~/mesh && cp mesh.example.yaml ~/mesh/mesh.yaml   # edit nodes and IPs
./gen.py ~/mesh/mesh.yaml
sudo ./install.sh ~/mesh desktop                        # on a systemd node
./install-openwrt.sh ~/mesh stick root@192.168.1.1      # bundle for the node's arch
```

The first install on a node generates `/etc/wireguard/wgmesh.key` and prints
its public key. Put it in `mesh.yaml` as `pubkey`, run `gen.py` again, and
reinstall every node. Private keys never leave their node.

Node requirements: `wireguard-tools`, `avahi-daemon` (OpenWrt: `avahi-dbus-daemon`),
`avahi-utils`, `curl`, `base64`. OpenWrt nodes treat the mesh like LAN
(firewall zone 0) and accept WireGuard and mDNS from `wan`.
