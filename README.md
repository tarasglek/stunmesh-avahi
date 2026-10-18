# stunmesh-avahi

[stunmesh-go](https://github.com/tjjh89017/stunmesh-go) shell plugin that lets peers on the same LAN talk directly.

stunmesh only publishes each node's public ip:port. Two nodes behind the same router then try to reach each other via the router's public IP, which fails unless the router hairpins UDP. You can't fix every router a laptop visits.

stunmesh-avahi wraps your real store plugin (OpenDHT, Cloudflare, anything speaking the shell protocol):

- **set**: advertises the WireGuard device as an avahi static service (`_wgmesh._udp`, WG port, `pk=<wg pubkey>`), remembers our public IP from the record, passes the request on.
- **get**: passes the request on and opens the peer's record. If the peer is behind our public IP (or the store is down) and avahi sees the peer's key, answers with its LAN ip:port instead.

Same number of store calls as the plugin alone. Stale mDNS is ignored once the peer publishes a different public IP. Peers are matched by WG key, not hostname. The LAN answer is sealed exactly like stunmesh's own records.

## Requirements

- Linux, stunmesh-go running as root
- `wg`, `avahi-daemon`, `avahi-browse`
- A shell store plugin, e.g. `stunmesh-opendht-shell` from the stunmesh-go plugins release

## Install

```sh
go install github.com/tarasglek/stunmesh-avahi@latest
```

Or download `stunmesh-avahi-linux-amd64` from releases.

Releases also ship `stunmesh-bundle-linux-<arch>-<version>.tar.gz`, everything to run a whole mesh on systemd and OpenWrt nodes: stunmesh-go and stunmesh-avahi merged into one binary with [makebb](https://github.com/u-root/gobusybox) (about 26% smaller than the two), `stunmesh-opendht-shell`, a config generator, installers and service units. It holds no site config: your `mesh.yaml` and the configs rendered from it stay with you. See [deploy/README.md](deploy/README.md).

## Release

```sh
git tag vX.Y.Z && git push --tags
make release   # builds dist/ for ARCHES (amd64 arm64), uploads with gh
```

`make dist` builds without uploading. Pins: `STUNMESH_VERSION` (and its `STUNMESH_COMMIT`), `MAKEBB_VERSION`, `GO_VERSION`. Builds are reproducible: the same commit gives byte-identical artifacts and `SHA256SUMS`, regardless of checkout path or umask.

## Config

```yaml
interfaces:
  wgmesh:
    peers:
      node-b:
        public_key: "<wg-pubkey-of-node-b>"
        plugin: avahi-then-dht
plugins:
  avahi-then-dht:
    type: shell
    command: /usr/local/bin/stunmesh-avahi
    args:
      - -dev=wgmesh
      - --
      - /usr/local/bin/stunmesh-opendht-shell
      - -endpoint
      - https://dhtproxy2.jami.net
    dedup: false
```

Everything after `--` is the store plugin and its args. Restart stunmesh after config changes.

Writes:

- `/etc/avahi/services/stunmesh-<dev>.service`, only when port or key changes
- `/run/stunmesh-avahi/<dev>`, our last public IPv4

## Limits

- IPv4 only: stunmesh's Linux WG client drops IPv6 link-local zones.
- No reachability check: if avahi sees the peer but UDP between them is blocked, the LAN IP is still used.
- No multicast (guest Wi-Fi, client isolation): falls back to the store's public IP.

## License

LGPL-3.0-or-later, same as stunmesh-go.
