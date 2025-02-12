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
        self.version = buffer[0] >> 4
        self.header_len = (buffer[0] & 0xF) * 4
        self.tos = buffer[1]
        self.length = int.from_bytes(buffer[2:4], byteorder='big')
        self.id = int.from_bytes(buffer[4:6], byteorder='big')
        self.flags = buffer[6] >> 5
        self.frag_offset = int.from_bytes(buffer[6:8], byteorder='big') & 0x1FFF
        self.ttl = buffer[8]
        self.proto = buffer[9]
        self.cksum = int.from_bytes(buffer[10:12], byteorder='big')
        self.src = '.'.join(map(str, buffer[12:16]))
        self.dst = '.'.join(map(str, buffer[16:20]))

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
        self.type = buffer[0]
        self.code = buffer[1]
        self.cksum = int.from_bytes(buffer[2:4], byteorder='big')

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
        self.src_port = int.from_bytes(buffer[0:2], byteorder='big')
        self.dst_port = int.from_bytes(buffer[2:4], byteorder='big')
        self.len = int.from_bytes(buffer[4:6], byteorder='big')
        self.cksum = int.from_bytes(buffer[6:8], byteorder='big')


    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like
def check_udp_match(buf, dest_ip):
    ipv4 = IPv4(buf[:20])
    icmp_start = ipv4.header_len
    icmp_payload_start = icmp_start + 8
    original_ip = IPv4(buf[icmp_payload_start:icmp_payload_start+20])
    original_udp = UDP(buf[icmp_payload_start+20:icmp_payload_start+28])
    return original_ip.dst == dest_ip and original_udp.dst_port 

def check_trunc_buff(buf):
    if len(buf) < 20:
        return True
    ipv4header = IPv4(buf[:20])
    if len(buf) < ipv4header.length:
        return True
    icmp_start = ipv4header.header_len
    if len(buf) < icmp_start + 4:
        return True
    return False

def check_cant_parse(buf):          
    try:
        ipv4header = IPv4(buf[:20])
        icmp_start = ipv4header.header_len
        ICMP(buf[icmp_start:icmp_start+4])
        return False
    except (IndexError, ValueError):
        return True
def probe_push(sock, dest_ip, ttl, port):
    # set ttl on socket and send a probe packet with my personal payload hehehe
    print(f"Sending probe to {dest_ip} with TTL {ttl}") 
    sock.set_ttl(ttl)
    print(f"ttl set: {ttl}")
    sock.sendto("dumdum".encode(), (dest_ip, port))
    print(f"Socket dumdum sent to: {dest_ip}")
def packet_recv(rcvsock):
    print("Waiting for packet... Be patient.")
    # wait for a packet to be ready and receive itif available
    if rcvsock.recv_select():
        data, addr = rcvsock.recvfrom()
        print(f"Received packet from {addr}")
        return data, addr
    print("No packet received :/ Finding other branches...")
    return None, None
def reply_read_append(buf, dest_ip, router_setter):
    #b5 and b6 trunc buff and unparasable
    if check_trunc_buff(buf) or check_cant_parse(buf):
        return False
    #header
    ipv4header = IPv4(buf[:20])
    #valid network ip id
    if ipv4header.proto != util.IPPROTO_ICMP:
        return False
    
    icmp_start = ipv4header.header_len
    icmp = ICMP(buf[icmp_start:icmp_start+4])
    #not unreachable or time exceeded
    if icmp.type not in [11, 3]:
        return False
    #unreachable but not ttl related
    if icmp.type == 11 and icmp.code != 0:
        return False


    router_setter.add(ipv4header.src)
    return dest_ip == ipv4header.src

def single_TTL_iter(ttl, sndsock, rcvsock, dest_ip, port):
    locally_set = set()
    found_dest = False
    seen_probes = set()  #track dup responses
    
    for _ in range(PROBE_ATTEMPT_COUNT):
        probe_push(sndsock, dest_ip, ttl, port)
        
        while rcvsock.recv_select() and not len(locally_set) == PROBE_ATTEMPT_COUNT:
            buf, _ = rcvsock.recvfrom()
            if not buf:
                continue
            
        # heck if truncated or unparseble
        if check_trunc_buff(buf) or check_cant_parse(buf):
            continue
        
        # parse ipv4 header
        try:
            ipv4_response = IPv4(buf[:20])
        except:
            continue  # invalid ipv4 header
        
        # check if icmp
        if ipv4_response.proto != util.IPPROTO_ICMP:
            continue
        
        #parse icmp header
        icmp_start = ipv4_response.header_len
        try:
            icmp = ICMP(buf[icmp_start:icmp_start+4])
        except IndexError:
            continue  # not enough data
        
        #check type and code
        if icmp.type not in [11, 3] or (icmp.type == 11 and icmp.code != 0):
            continue
        
        #parse original ip & udp headers
        icmp_payload_start = icmp_start + 8
        try:
            original_ip = IPv4(buf[icmp_payload_start:icmp_payload_start+20])
            original_udp = UDP(buf[icmp_payload_start+20:icmp_payload_start+28])
        except (IndexError, ValueError):
            continue  #not enough data
        
        #check udp dst port
        if original_udp.dst_port != TRACEROUTE_PORT_NUMBER:
            continue
        
        #gen a nique key for probe, orig ip id, idp src, and udp dst
        key = (original_ip.id, original_udp.src_port, original_udp.dst_port, original_ip.ttl)
        if key in seen_probes:
            continue  # dup response
        
        #update local set with router's ip 
        locally_set.add(ipv4_response.src)
        
        #check if response is from dest 
        if ipv4_response.src == dest_ip:
            found_dest = True

    return list(locally_set), found_dest
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
    print(f"Starting the traceroute to {ip} Setting up for probing.")

    the_traceroute = []
    ttl = 1
    found_dest = False
    received = 0

    while True:
        print(f"Probing a single ttl iteration... {ttl}")
        curr_ttl_routers, found_dest = single_TTL_iter(ttl, sendsock, recvsock, ip, TRACEROUTE_PORT_NUMBER)
        util.print_result(curr_ttl_routers, ttl)        
        the_traceroute.append(curr_ttl_routers)
        

        if ttl >= TRACEROUTE_MAX_TTL or found_dest or received == 30:
            break

        ttl+=1
        received+=1


    return the_traceroute
if __name__ == '__main__':
    try:
        args = util.parse_args()
        ip_addr = util.gethostbyname(args.host)
        print(f"Task: Finding traceroute to {args.host} ({ip_addr})")
        sendsock = util.Socket.make_udp()
        recvsock = util.Socket.make_icmp()
        print("Sockets successfully created!!")
        result = traceroute(sendsock, recvsock, ip_addr)
        print("Traceroute completed! Cool")
        print(result)
    except util.Socket.Error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"Some error occurred: ->>> {e}")