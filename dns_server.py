"""
dns_server.py – Captive Portal DNS Redirector
===============================================
Listens on UDP port 53 and answers ALL DNS queries with the portal IP.
This causes every HTTP/HTTPS request from connected clients to hit the
Flask server, where they are shown the captive portal page.

Requirements:
  • Run as Administrator (port 53 is privileged).
  • Windows Firewall must allow UDP/53 inbound on the hotspot interface.

The server uses only the Python standard library (socket + struct) – no
third‑party DNS library is needed.

Architecture
------------
  Client DNS query  →  this server  →  always returns PORTAL_IP
  Client browser    →  PORTAL_IP:80 / :5000  →  Flask captive portal
"""

import socket
import struct
import threading
import signal
import sys

# ─── Configuration ────────────────────────────────────────────────────────────

# IP of this machine on the hotspot network (Windows Mobile Hotspot default)
PORTAL_IP   = "192.168.137.1"
DNS_PORT    = 53          # Standard DNS port (requires admin)
BUFFER_SIZE = 4096

# ─── DNS Packet Helpers ────────────────────────────────────────────────────────

def parse_dns_query(data: bytes):
    """
    Extract the transaction ID and queried domain name from a raw DNS query.
    Returns (txn_id: int, domain: str).
    """
    txn_id = struct.unpack("!H", data[:2])[0]

    # Parse QNAME starting at byte 12
    domain_parts = []
    idx = 12
    while idx < len(data):
        length = data[idx]
        if length == 0:
            break
        idx += 1
        domain_parts.append(data[idx: idx + length].decode("utf-8", errors="replace"))
        idx += length
    domain = ".".join(domain_parts)
    return txn_id, domain


def build_dns_response(data: bytes, redirect_ip: str) -> bytes:
    """
    Build a DNS response that resolves every query to *redirect_ip*.
    Supports both A (IPv4) record answers only – good enough for captive portal.

    Packet structure (RFC 1035):
      Header  : 12 bytes
      Question: copied from query
      Answer  : synthesised A record
    """
    txn_id = data[:2]

    # Flags: QR=1(response), AA=1(authoritative), RCODE=0(no error)
    flags = struct.pack("!H", 0x8400)

    # QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    counts = struct.pack("!HHHH", 1, 1, 0, 0)

    # Copy the question section verbatim (starts at byte 12)
    question_section = data[12:]

    # Answer section
    # NAME: pointer to offset 12 (0xC00C) – standard DNS compression
    name_ptr  = b"\xc0\x0c"
    rtype     = struct.pack("!H", 1)       # A record
    rclass    = struct.pack("!H", 1)       # IN (internet)
    ttl       = struct.pack("!I", 60)      # 60‑second TTL keeps redirects snappy
    rdlength  = struct.pack("!H", 4)       # IPv4 = 4 bytes
    rdata     = socket.inet_aton(redirect_ip)

    answer = name_ptr + rtype + rclass + ttl + rdlength + rdata

    return txn_id + flags + counts + question_section + answer


# ─── Server ───────────────────────────────────────────────────────────────────

class DNSServer:
    def __init__(self, bind_ip: str = "0.0.0.0", port: int = DNS_PORT,
                 redirect_ip: str = PORTAL_IP):
        self.bind_ip     = bind_ip
        self.port        = port
        self.redirect_ip = redirect_ip
        self._sock       = None
        self._running    = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.bind_ip, self.port))
        except PermissionError:
            print(
                f"[DNS] Cannot bind to port {self.port}. "
                "Run this script as Administrator."
            )
            sys.exit(1)

        self._running = True
        print(
            f"[DNS] Listening on {self.bind_ip}:{self.port} "
            f"-> redirecting all queries to {self.redirect_ip}"
        )

        while self._running:
            try:
                data, addr = self._sock.recvfrom(BUFFER_SIZE)
                # Handle each query in a thread so we don't block
                t = threading.Thread(
                    target=self._handle_query,
                    args=(data, addr),
                    daemon=True,
                )
                t.start()
            except OSError:
                # Socket closed during shutdown
                break

        print("[DNS] Server stopped.")

    def _handle_query(self, data: bytes, addr):
        """Process one DNS query and send back the spoofed response."""
        try:
            txn_id, domain = parse_dns_query(data)
            response = build_dns_response(data, self.redirect_ip)
            self._sock.sendto(response, addr)
            print(f"[DNS] {addr[0]}:{addr[1]}  {domain!r}  →  {self.redirect_ip}")
        except Exception as exc:
            print(f"[DNS] Error handling query from {addr}: {exc}")

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = DNSServer()

    def _shutdown(sig, frame):
        print("\n[DNS] Shutting down …")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    server.start()
