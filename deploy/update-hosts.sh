#!/bin/sh
# Replace the wgmesh block in /etc/hosts with FILE. Same "# profile.on wgmesh
# ... # end" block hostctl writes, so a block from hostctl is replaced too.
#   update-hosts.sh FILE
set -eu
tmp=$(mktemp)
{
	awk '/^# profile\.(on|off) wgmesh$/{s=1;next} s&&/^# end$/{s=0;next} !s' /etc/hosts
	echo '# profile.on wgmesh'
	cat "$1"
	echo '# end'
} >"$tmp"
cat "$tmp" >/etc/hosts
rm "$tmp"
