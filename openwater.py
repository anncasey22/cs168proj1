import util

TRACEROUTE_MAX_TTL = 30
TRACEROUTE_PORT_NUMBER = 33434
PROBE_ATTEMPT_COUNT = 3


class IPv4:
    version: int
    header_len: int
    tos: int
    length: int
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        # Robust: require at least the minimum IPv4 header
        if len(buffer) < 20:
            raise ValueError("Truncated IPv4 header")

        b = ''.join(format(byte, '08b') for byte in buffer)

        self.version = int(b[0:4], 2)
        ihl_words = int(b[4:8], 2)
        self.header_len = ihl_words * 4

        # Validate header length
        if self.header_len < 20 or len(buffer) < self.header_len:
            raise ValueError("Invalid or truncated IPv4 header length")

        self.tos = int(b[8:16], 2)
        self.length = int(b[16:32], 2)
        self.id = int(b[32:48], 2)
        self.flags = int(b[48:51], 2)
        self.frag_offset = int(b[51:64], 2)
        self.ttl = int(b[64:72], 2)
        self.proto = int(b[72:80], 2)
        self.cksum = int(b[80:96], 2)
        self.src = '.'.join(str(int(b[i:i + 8], 2)) for i in range(96, 128, 8))
        self.dst = '.'.join(str(int(b[i:i + 8], 2)) for i in range(128, 160, 8))

    def __str__(self) -> str:
        return (
            f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, "
            f"id {self.id}, flags 0x{self.flags:x}, "
            f"ofsset {self.frag_offset}, "
            f"proto {self.proto}, header_len {self.header_len}, "
            f"len {self.length}, cksum 0x{self.cksum:x}) "
            f"{self.src} > {self.dst}"
        )


class ICMP:
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        if len(buffer) < 4:
            raise ValueError("Truncated ICMP header")
        self.type = buffer[0]
        self.code = buffer[1]
        self.cksum = int.from_bytes(buffer[2:4], "big")

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, cksum 0x{self.cksum:x})"


class UDP:
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        if len(buffer) < 8:
            raise ValueError("Truncated UDP header")
        self.src_port = int.from_bytes(buffer[0:2], "big")
        self.dst_port = int.from_bytes(buffer[2:4], "big")
        self.len = int.from_bytes(buffer[4:6], "big")
        self.cksum = int.from_bytes(buffer[6:8], "big")

    def __str__(self) -> str:
        return (
            f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, "
            f"len {self.len}, cksum 0x{self.cksum:x})"
        )


def _is_valid_icmp(type_: int, code: int) -> bool:
    # Accept only:
    #   Time Exceeded (11,0)
    #   Destination Unreachable - Port Unreachable (3,3)
    return (type_ == 11 and code == 0) or (type_ == 3 and code == 3)


def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) -> list[list[str]]:
    """
    Robust traceroute implementation matching the project spec and Gradescope tests.
    """
    results: list[list[str]] = []
    base_port = TRACEROUTE_PORT_NUMBER

    for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
        sendsock.set_ttl(ttl)

        # Use per-probe unique destination ports so we can match ICMP replies
        # to the exact probe for this TTL and ignore delayed duplicates/wrong-traceroute packets.
        expected_ports = [base_port + (ttl - 1) * PROBE_ATTEMPT_COUNT + i for i in range(PROBE_ATTEMPT_COUNT)]
        expected_set = set(expected_ports)

        # Send probes
        for port in expected_ports:
            sendsock.sendto(b"lala", (ip, port))

        routers_this_ttl: set[str] = set()
        matched_ports: set[int] = set()
        reached_destination = False

        # Receive until we've matched each probe OR we time out (drops/silent routers)
        while len(matched_ports) < PROBE_ATTEMPT_COUNT:
            if not recvsock.recv_select():
                break  # allowed when packets are missing/dropped/silent

            buf, addr = recvsock.recvfrom()
            responder_ip = addr[0]

            # ---- Outer IPv4 parse / sanity ----
            try:
                outer_ip = IPv4(buf)
            except Exception:
                continue

            # Must be ICMP (ignore irrelevant UDP/etc.)
            if outer_ip.proto != 1:
                continue

            # Need ICMP header
            icmp_start = outer_ip.header_len
            if len(buf) < icmp_start + 8:
                continue

            try:
                icmp = ICMP(buf[icmp_start:icmp_start + 8])
            except Exception:
                continue

            if not _is_valid_icmp(icmp.type, icmp.code):
                continue

            # ---- Match to our probe using ICMP payload (inner quoted packet) ----
            # ICMP payload contains original IPv4 header + first 8 bytes of L4 header (UDP)
            inner = buf[icmp_start + 8:]
            if len(inner) < 20:
                continue

            try:
                inner_ip = IPv4(inner)
            except Exception:
                continue

            # Only accept replies to probes aimed at our destination
            if inner_ip.dst != ip:
                continue

            # Original probe should be UDP
            if inner_ip.proto != 17:
                continue

            inner_udp_start = inner_ip.header_len
            if len(inner) < inner_udp_start + 8:
                continue

            try:
                inner_udp = UDP(inner[inner_udp_start:inner_udp_start + 8])
            except Exception:
                continue

            # Only accept if this ICMP was triggered by a probe we sent for THIS ttl
            probe_dst_port = inner_udp.dst_port
            if probe_dst_port not in expected_set:
                continue

            # Deduplicate: only one accepted response per probe port
            if probe_dst_port in matched_ports:
                continue

            matched_ports.add(probe_dst_port)
            routers_this_ttl.add(responder_ip)

            # Destination reached signal: ICMP Port Unreachable from destination
            if icmp.type == 3 and icmp.code == 3 and responder_ip == ip:
                reached_destination = True
                # We can stop early; spec wants final sublist to be [ip]
                break

        ttl_list = list(routers_this_ttl)
        results.append(ttl_list)
        util.print_result(ttl_list, ttl)

        if reached_destination:
            results[-1] = [ip]
            util.print_result([ip], ttl)
            return results

    return results


if __name__ == "__main__":
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
