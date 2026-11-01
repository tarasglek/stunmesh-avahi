# stunmesh-avahi

Two [stunmesh-go](https://github.com/tjjh89017/stunmesh-go) plugins, and a
stunmesh-go binary with them compiled in, for a WireGuard mesh that costs
next to nothing on metered links and works between peers on the same LAN.

- **avahi**: stunmesh only publishes each node's public ip:port, so two
  nodes behind the same router try to reach each other through its public
  IP, which fails unless the router hairpins UDP. avahi advertises the
  WireGuard device over mDNS and, when a peer shares our public IP and is
  visible on the LAN, answers with its LAN ip:port instead.
- **lease**: publishes our record only when it changes or before the DHT
  expires it, skips lookups of peers with a fresh WireGuard handshake, and
  quiets peers that are away: their lookups back off to every 4 minutes
  and, with `keepalive` set, their WireGuard keepalive is off until they
  return.

Both wrap another plugin instance through stunmesh-go's public plugin API
([#320](https://github.com/tjjh89017/stunmesh-go/issues/320)), so they work
with any store, not only OpenDHT.

## Config

```yaml
interfaces:
  wgmesh:
    peers:
      node-b:
        public_key: "<wg-pubkey-of-node-b>"
        plugin: mesh
plugins:
  dht:
    type: builtin
    name: opendht
    endpoints: ["http://dhtproxy2.jami.net", "http://dhtproxy3.jami.net", "https://dhtproxy2.jami.net"]
  leased:
    type: builtin
    name: lease
    next: dht
    keepalive: 25s   # the WireGuard config's persistent keepalive; omit to leave keepalives alone
  mesh:
    type: builtin
    name: avahi
    next: leased
```

lease also takes `republish` (default `7m30s`) and `fresh` (default `3m`).
Keep `republish` plus stunmesh's `refresh_interval` under the store's expiry
(10 minutes for OpenDHT).

avahi writes `/etc/avahi/services/stunmesh-<device>.service`, only when the
port or key changes.

## Measured

On an OpenWrt LTE stick with 6 peers, one of them offline, DHT traffic
including IP headers, over 10 minutes each:

| Setup | DHT per day | WireGuard to the offline peer per day |
|---|---|---|
| shell plugins, https | ~196 MB | ~2.1 MB |
| avahi, lease, opendht, https | ~7.5 MB | ~2.1 MB |
| same, plain http | ~2.4 MB | ~2.1 MB |
| same, with `keepalive` | ~1.3 MB | 0 |

## Build and run

```sh
make check   # build for this host, run the tests and a plugin-chain smoke test
make dist    # release bundles for ARCHES (amd64 arm64) in dist/
```

`cmd/stunmesh-go` is upstream's `main.go` linking `builtin/opendht` and
these plugins. `go.mod` pins stunmesh-go; `GO_VERSION` pins the toolchain.
Builds are reproducible: the same commit gives byte-identical bundles.

Each bundle, `stunmesh-bundle-linux-<arch>-<version>.tar.gz`, holds the
binary, a config generator, installers and service units for systemd and
OpenWrt nodes, and no site config. See [deploy/README.md](deploy/README.md).

Release: tag, push the tag, `make release`.

## Limits

- IPv4 only: live and LAN answers are IPv4 records.
- avahi does not check reachability: if mDNS sees the peer but UDP between
  them is blocked, the LAN IP is still used.
- No multicast (guest Wi-Fi, client isolation): avahi falls back to the
  store's record.
- A peer that comes back after being away can take up to 4 minutes to be
  looked up again, unless it reaches us first.

## License

LGPL-3.0-or-later, same as stunmesh-go.
