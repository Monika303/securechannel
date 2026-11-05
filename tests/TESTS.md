# Secure Channel Test Results

| Test | Command / method | Expected Result | Actual Result |
|---|---|---|---|
| Handshake | start Dev2, then Dev1 | Handshake OK on both | Passed |
| Encryption on the wire | tcpdump on Dev1-Dev2 link | payload unreadable | Passed |
| Headers visible | tcpdump | IPs, ports, seq readable | Passed |
| Size +16 bytes | compare packet length | exactly +16 | Passed |
| File integrity | 1 MB random file via nc | identical sha256 | Passed |
| Unique nonces | sort \| uniq -d on log | empty output | Passed |
| Wrong PSK | Dev1 with bad.key | authentication failed | Passed |
| Replay | REPLAY=1 | duplicate dropped | Passed |
| Tamper (ct / tag / ack) | TAMPER=... | tag check fails, TCP recovers | Passed |
| Packet loss | netem loss 5% | transfer still correct | Passed |
| Other port untouched | port 6000 | readable, no [ENC] | Passed |
