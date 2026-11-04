#!/bin/bash
set -e

# clean up from earlier runs
for ns in pc1 dev1 dev2 pc2; do 
    ip netns del $ns 2>/dev/null || true
done

for ns in pc1 dev1 dev2 pc2; do 
    ip netns add $ns
    ip -n $ns link set lo up
done

# links: pc1-dev1, dev1-dev2, dev2-pc2
ip link add p1d1 type veth peer name d1p1
ip link add d1d2 type veth peer name d2d1
ip link add d2p2 type veth peer name p2d2

ip link set p1d1 netns pc1
ip link set d1p1 netns dev1
ip link set d1d2 netns dev1
ip link set d2d1 netns dev2
ip link set d2p2 netns dev2
ip link set p2d2 netns pc2

ip -n pc1  addr add 10.0.1.2/24 dev p1d1
ip -n dev1 addr add 10.0.1.1/24 dev d1p1
ip -n dev1 addr add 10.0.2.1/24 dev d1d2
ip -n dev2 addr add 10.0.2.2/24 dev d2d1
ip -n dev2 addr add 10.0.3.1/24 dev d2p2
ip -n pc2  addr add 10.0.3.2/24 dev p2d2

# small MTU, because encryption adds 16 bytes (the GCM tag) to each packet
for pair in "pc1 p1d1" "dev1 d1p1" "dev1 d1d2" "dev2 d2d1" "dev2 d2p2" "pc2 p2d2"; do
  set -- $pair
  ip -n $1 link set $2 mtu 1400 up
  # disable checksum/segmentation offload
  ip netns exec $1 ethtool -K $2 tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
done

# routing
ip -n pc1  route add default via 10.0.1.1
ip -n pc2  route add default via 10.0.3.1
ip -n dev1 route add 10.0.3.0/24 via 10.0.2.2
ip -n dev2 route add 10.0.1.0/24 via 10.0.2.1

ip netns exec dev1 sysctl -qw net.ipv4.ip_forward=1
ip netns exec dev2 sysctl -qw net.ipv4.ip_forward=1

echo "Topology ready"
