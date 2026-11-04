#!/bin/bash
# Dev1
ip netns exec dev1 iptables -F FORWARD
ip netns exec dev1 iptables -A FORWARD -i d1p1 -p tcp --dport 5000 -j NFQUEUE --queue-num 0
ip netns exec dev1 iptables -A FORWARD -i d1d2 -p tcp --sport 5000 -j NFQUEUE --queue-num 1

# Dev2
ip netns exec dev2 iptables -F FORWARD
ip netns exec dev2 iptables -A FORWARD -i d2p2 -p tcp --sport 5000 -j NFQUEUE --queue-num 0
ip netns exec dev2 iptables -A FORWARD -i d2d1 -p tcp --dport 5000 -j NFQUEUE --queue-num 1
echo "Rules installed"
