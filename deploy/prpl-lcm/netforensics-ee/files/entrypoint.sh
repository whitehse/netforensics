#!/bin/sh
# netforensics EE entrypoint (Profile A full / Profile B --demo)
# Runs under LXC / prpl LCM (cthulhu-lxc). Host netns required for live modes.

set -eu

DEMO=0
ROUTER_ID="${ROUTER_ID:-}"
if [ -z "${ROUTER_ID}" ] && [ -r /proc/sys/kernel/hostname ]; then
	ROUTER_ID=$(cat /proc/sys/kernel/hostname)
fi
ROUTER_ID="${ROUTER_ID:-cpe}"

for arg in "$@"; do
	case "$arg" in
	--demo) DEMO=1 ;;
	esac
done

mkdir -p /var/spool/netforensics

# Apply sysctl only if we appear to be host-capable (ignore failures in EE)
if [ -r /etc/netforensics/99-forensics.conf.HOST_APPLY ]; then
	# Prefer host apply; inside EE this may be a no-op under restrictions
	true
fi

start_forensicsd() {
	if [ ! -x /usr/sbin/forensicsd ]; then
		return 0
	fi
	if [ "$DEMO" -eq 1 ]; then
		/usr/sbin/forensicsd --demo --router-id "$ROUTER_ID" &
	else
		# Live: needs CAP_NET_ADMIN + host netns
		/usr/sbin/forensicsd --netlink --router-id "$ROUTER_ID" \
			--wifi-if "${WIFI_IF:-wlan0}" --wifi-interval-ms 10000 &
	fi
	echo $! >/var/run/forensicsd.pid 2>/dev/null || true
}

start_cpe_agent() {
	if [ ! -x /usr/sbin/cpe_agent ]; then
		return 0
	fi
	CFG=/etc/cpe_agent/cpe_agent.yaml
	if [ "$DEMO" -eq 1 ]; then
		/usr/sbin/cpe_agent --config "$CFG" --router-id "$ROUTER_ID" --demo &
	else
		/usr/sbin/cpe_agent --config "$CFG" --router-id "$ROUTER_ID" &
	fi
	echo $! >/var/run/cpe_agent.pid 2>/dev/null || true
}

term() {
	for p in /var/run/cpe_agent.pid /var/run/forensicsd.pid; do
		if [ -r "$p" ]; then
			kill "$(cat "$p")" 2>/dev/null || true
		fi
	done
	exit 0
}
trap term INT TERM

start_forensicsd
start_cpe_agent

# Keep EE alive while children run
while true; do
	sleep 3600
done
