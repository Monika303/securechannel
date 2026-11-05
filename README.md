# Secure Inline Communication Channel

Linux prototype: PC1 -> Device1 -> Device2 -> PC2. The devices protect selected TCP/IPv4 traffic (port 5000) with AES-256-GCM. Only the TCP payload is encrypted; IP and TCP headers are preserved. No UDP encapsulation, no custom protocol header.

## How it works
1. **Handshake** (control TCP connection, port 9000): ffdhe2048 Diffie-Hellman, authenticated with a pre-shared key (HMAC-SHA256 over the transcript), keys derived with HKDF-SHA256 (separate key and salt per direction).
2. **Sending device**: replaces the payload with `ciphertext || 16-byte tag`, updates IP length, recalculates IP and TCP checksums.
3. **Receiving device**: verifies the tag, decrypts, restores the original packet, recalculates lengths and checksums, forwards it.
4. **Interception**: iptables FORWARD rules send matching packets to NFQUEUE (queue 0 = encrypt, queue 1 = decrypt).

## Nonce design
`nonce (12 B) = salt(4) | IP id(2) | TCP seq(4) | client port(2)`
- Salt and key differ per direction, so directions can never collide.
- The sender stores every used nonce and drops a packet that would reuse one.
- The receiver stores accepted nonces (only after the tag verifies) -> replay protection.

## Authenticated data (AAD)
src/dst IP, ports, TCP seq, ack and flags.

## Requirements
Ubuntu (tested in VirtualBox), OpenSSL 3.x, libnetfilter-queue-dev, iproute2, iptables.
```bash
sudo apt install -y build-essential libssl-dev libnetfilter-queue-dev \
    iproute2 iptables tcpdump ethtool iperf3 netcat-openbsd
