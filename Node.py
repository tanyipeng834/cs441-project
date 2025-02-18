import socket
import threading
import sys
from EthernetFrame import EthernetFrame
from IPPacket import IPPacket
import traceback

class Node:
    MAX_DATA_LENGTH = 256
    HOST_IP = '127.0.0.1'
    BASE_PORT = 50000

    # IP address mapping
    MAC_TO_IP = {
        "N1": 0x1A,
        "N2": 0x2A,
        "N3": 0x2B,
        "R1": 0x11,
        "R2": 0x21
    }

    # IP to MAC address mapping
    IP_TO_MAC = {
        0x1A: "N1",
        0x2A: "N2",
        0x2B: "N3",
        0x11: "R1",
        0x21: "R2"
    }

    # Routing table for each node
    ROUTING_TABLE = {
        "N1": {0x2A: 0x11, 0x2B: 0x11},  # Route to LAN2 via R1
        "N2": {0x1A: 0x21},              # Route to LAN1 via R2
        "N3": {0x1A: 0x21},              # Route to LAN1 via R2
        "R1": {0x2A: 0x21, 0x2B: 0x21},  # Route to LAN2 via R2
        "R2": {0x1A: 0x11}               # Route to LAN1 via R1
    }

    def __init__(self, mac_address, port, network):
        self.mac_address = mac_address
        self.port = port
        self.network = network
        self.ip_address = self.MAC_TO_IP.get(mac_address)
        self.is_router = mac_address.startswith('R')

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((Node.HOST_IP, self.port))
            self.sock.listen(1)
        except socket.error as e:
            print(f"Error starting node on port {self.port}: {e}")
            sys.exit(1)

        print(f"Node {self.mac_address} started on port {self.port}.")

        self.is_running = True
        self.listen_thread = threading.Thread(target=self.listen_for_frames)
        self.listen_thread.start()

    def get_next_hop(self, destination_ip):
        """
        Get next hop IP address for the destination
        """
        if destination_ip == self.ip_address:
            return None  # Packet for this node
        
        # Check routing table
        if self.mac_address in self.ROUTING_TABLE:
            next_hop = self.ROUTING_TABLE[self.mac_address].get(destination_ip)
            if next_hop is not None:
                return next_hop
        
        # If we're a router, check if destination is directly connected
        if self.is_router:
            if destination_ip in self.IP_TO_MAC:
                return destination_ip
                
        return None

    def send_frame(self, destination, data):
        """
        Send a frame to all other nodes in the same network (Ethernet broadcast).
        """
        for node in self.network.nodes:
            if node == self:
                continue

            destination_port = self.process_node_mac(node.mac_address)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((Node.HOST_IP, destination_port))
                    frame = EthernetFrame(self.mac_address, destination, data)
                    s.sendall(frame.encode())
            except Exception as e:
                print(f"Error sending frame from {self.mac_address} to {destination_port}: {e}")

    def send_ip_packet(self, destination_ip, protocol, data):
        """
        Create and send an IP packet with routing
        """
        # Create IP packet
        ip_packet = IPPacket(self.ip_address, destination_ip, protocol, data)
        
        # Get next hop from routing table
        next_hop = self.get_next_hop(destination_ip)
        
        if next_hop is None and destination_ip in self.IP_TO_MAC:
            # Direct delivery
            destination_mac = self.IP_TO_MAC[destination_ip]
            self.send_frame(destination_mac, ip_packet.encode())
        elif next_hop is not None:
            # Forward to next hop
            next_hop_mac = self.IP_TO_MAC[next_hop]
            self.send_frame(next_hop_mac, ip_packet.encode())
        else:
            print(f"No route to host {hex(destination_ip)}")

    def process_node_mac(self, mac_address):
        if mac_address[-2] == 'R':
            port = Node.BASE_PORT + 3 + int(mac_address[-1])
        else:
            port = Node.BASE_PORT + int(mac_address[-1])
        return port

    def listen_for_frames(self):
        while self.is_running:
            try:
                conn, addr = self.sock.accept()
                with conn:
                    raw_data = conn.recv(2 + 2 + 1 + Node.MAX_DATA_LENGTH)
                    if not raw_data:
                        continue
                    frame = raw_data.decode('utf-8')
                    self.process_frame(frame)
            except OSError:
                if self.is_running:
                    print(f"Node {self.mac_address} socket accept() error.")
                break
            except Exception as e:
                print("Error in listen_for_frames:")
                traceback.print_exc()

    def process_frame(self, frame):
        """
        Process received Ethernet frame with routing support
        """
        if len(frame) < 5:
            print(f"Node {self.mac_address} received invalid frame: {frame}")
            return

        source = frame[0:2]
        destination = frame[2:4]
        data_length = ord(frame[4:5])
        data = frame[5:5 + data_length]

        if destination == self.mac_address:
            # Try to decode as IP packet only if it looks like one
            try:
                # Check for valid IP packet format
                if len(data) >= 4:
                    source_ip = ord(data[0])
                    dest_ip = ord(data[1])
                    protocol = ord(data[2])
                    
                    # Only process as IP if source and dest are valid IP addresses
                    if source_ip in self.IP_TO_MAC and dest_ip in self.IP_TO_MAC:
                        ip_packet = IPPacket.decode(data)
                        if ip_packet:
                            self.process_ip_packet(ip_packet)
                            return
            except Exception:
                pass  # Not an IP packet
                
            # Process as regular Ethernet data
            print(f"Node {self.mac_address} received data from {source}: {data}")
        else:
            print(f"Node {self.mac_address} dropped frame from {source} intended for {destination}")

    def process_ip_packet(self, packet):
        """
        Process received IP packet with routing support
        """
        print(f"Processing IP packet: src={hex(packet.source)}, dst={hex(packet.destination)}")
        
        if packet.destination == self.ip_address:
            # Handle packet intended for this node
            if packet.protocol == IPPacket.PROTOCOL_PING:
                if packet.data.startswith("REPLY:"):
                    print(f"Node {self.mac_address} received ping reply: {packet.data}")
                else:
                    print(f"Node {self.mac_address} received ping request: {packet.data}")
                    reply_data = f"REPLY: {packet.data}"
                    self.send_ip_packet(packet.source, IPPacket.PROTOCOL_PING, reply_data)
        elif self.is_router:
            # Router should forward the packet
            print(f"Router {self.mac_address} forwarding packet: {hex(packet.source)} -> {hex(packet.destination)}")
            next_hop = self.get_next_hop(packet.destination)
            if next_hop:
                next_hop_mac = self.IP_TO_MAC[next_hop]
                self.send_frame(next_hop_mac, packet.encode())
            else:
                print(f"Router {self.mac_address} has no route to {hex(packet.destination)}")
        else:
            print(f"Node {self.mac_address} dropping IP packet intended for {hex(packet.destination)}")

    def ping(self, destination_ip, message="PING"):
        """
        Send a ping to the specified IP address
        """
        print(f"Node {self.mac_address} pinging {hex(destination_ip)}: {message}")
        self.send_ip_packet(destination_ip, IPPacket.PROTOCOL_PING, message)

    def shutdown(self):
        self.is_running = False
        try:
            self.sock.close()
        except Exception as e:
            print(f"Error closing socket on port {self.port}: {e}")

        if self.listen_thread.is_alive():
            self.listen_thread.join()