import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):

        if len(buffer) < 20:
            raise ValueError
        
        buf = ''.join(format(byte, '08b') for byte in [*buffer])
        self.version = int(buf[:4],2)
        self.header_len = int(buf[4:8],2) *4 # Note length in bytes, not the value in the packet.

        if self.header_len < 20:
            raise ValueError

        self.tos = int(buf[8:16],2)       # Also called DSCP and ECN bits (i.e. on wikipedia).
        self.length = int(buf[16:32],2)      # Total length of the packet.
        self.id = int(buf[32:48],2)  
        self.flags =int(buf[48:51],2)  
        self.frag_offset= int(buf[51:64],2)  
        self.ttl = int(buf[64:72],2)  
        self.proto= int(buf[72:80],2)  
        self.cksum = int(buf[80:96],2)  
        self.src = '.'.join(str(int(buf[i:i+8], 2)) for i in range(96, 128, 8))
        self.dst = '.'.join(str(int(buf[i:i+8], 2)) for i in range(128, 160, 8))


    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):

        if len(buffer) < 4:
            raise ValueError

        self.type = buffer[0]
        self.code = buffer[1]
        self.cksum = int.from_bytes(buffer[2:4], "big")

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):

        if len(buffer) < 8:
            raise ValueError

        self.src_port = int.from_bytes(buffer[:2], "big")
        self.dst_port = int.from_bytes(buffer[2:4], "big")
        self.len =  int.from_bytes(buffer[4:6], "big")
        self.cksum = int.from_bytes(buffer[6:8], "big")

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

def valid_icmp(type: int, code: int)-> bool:
    if (code ==0 and type==11) or (code==3 and type==3):
        return True
    else:
        return False 

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """
    # sendsock.set_ttl(30)
    # sendsock.sendto("lala".encode(), (ip, TRACEROUTE_PORT_NUMBER))

    # if recvsock.recv_select():
    #     buf, address = recvsock.recvfrom()

    #     print("packet byte", buf.hex())
    #     print("ip", address[0])
    #     print("port", address[1])
        # return ("packet byte", buf.hex())
    
    # for ttl = 1..MAX:
        #   send PROBE_ATTEMPT_COUNT UDP probes with this ttl
        #   collect unique responder IPs for this ttl
        #   print_result(responders, ttl)
        #   append responders to result
        #   if any responder == destination OR ICMP type=3 code=3: stop and return
    result = []

    
    for ttl in range(1, TRACEROUTE_MAX_TTL+1):
        sendsock.set_ttl(ttl)

        test_ports = []
        ports_set = set()
        start = TRACEROUTE_PORT_NUMBER + (ttl - 1) * PROBE_ATTEMPT_COUNT
        for i in range(PROBE_ATTEMPT_COUNT):
            test_ports.append(start + i)
        ports_set = set(test_ports)

        for port in test_ports:
            sendsock.sendto(b'lala', (ip,port))

        reached_destination = False
        curr_routers = set()
        curr_ports = set()

        while len(curr_ports) < PROBE_ATTEMPT_COUNT:
            if not recvsock.recv_select():
                break #packets are not recieved 
            buf, addr = recvsock.recvfrom()
            responder_ip = addr[0]

            try:
                    outer_ip = IPv4(buf)
            except Exception:
                continue

            if outer_ip.proto != 1:
                continue

            icmp_start = outer_ip.header_len
            if len(buf) < icmp_start + 8:
                continue

            try:
                icmp = ICMP(buf[icmp_start:icmp_start + 8])
            except Exception:
                continue

            if not valid_icmp(icmp.type, icmp.code):
                continue

            inner = buf[icmp_start + 8:]
            if len(inner) < 20:
                continue

            try:
                inside = IPv4(inner)
            except Exception:
                continue
            if inside.dst != ip:
                    continue

            if inside.proto != 17:
                continue

            inside_udp_s = inside.header_len
            if len(inner) < inside_udp_s + 8:
                continue

            try:
                inside_udp = UDP(inner[inside_udp_s:inside_udp_s + 8])
            except Exception:
                continue

            dest_start = inside_udp.dst_port
            if dest_start not in ports_set:
                continue

            if dest_start in curr_ports:
                continue

            curr_ports.add(dest_start)
            curr_routers.add(responder_ip)

            if icmp.type == 3 and icmp.code == 3:
                reached_destination = True
                break
                
        ttl_list = list(curr_routers)
        result.append(ttl_list)
        util.print_result(ttl_list, ttl)

        if reached_destination:
            result[-1] = [ip]
            util.print_result([ip], ttl)
            return result
    return (result)


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
 
    

