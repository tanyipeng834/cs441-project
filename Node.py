import socket
import threading
import sys
import traceback
from EthernetFrame import EthernetFrame
from IPPacket import IPPacket, IP_ADDRESSES

class Node:
    MAX_DATA_LENGTH = 256
    HOST_IP = '127.0.0.1'
    BASE_PORT = 50000

    def __init__(self, mac_address, port, network):

        # Basic node properties
        self.mac_address = mac_address
        self.port = port
        self.network = network

        # IP configuration
        self.ip_address = IP_ADDRESSES[mac_address]
        self.router_interface = 'R1' if mac_address == 'N1' else 'R2'

        # Socket setup
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Allow reusing the address to avoid "Address already in use" in quick restarts
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((Node.HOST_IP, self.port))
            self.sock.listen(1)
        except socket.error as e:
            print(f"Error starting node on port {self.port}: {e}")
            sys.exit(1)

        print(f"Node {self.mac_address} started on port {self.port}.")

        # Flag to control the listening loop
        self.is_running = True

        # Start a non-daemon thread to listen for incoming frames
        self.listen_thread = threading.Thread(target=self.listen_for_frames)
        self.listen_thread.start()

    def get_next_hop(self, destination_ip):
        """Determine next hop for IP packets"""
        return self.router_interface
    
    def send_frame(self, destination, data):
        """
        Send a frame to all other nodes in the same network (Ethernet broadcast).
        Each node that receives it decides if it is the intended recipient or not.
        """
        for node in self.network.nodes:
            # Skip sending to itself
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
        """Send an IP packet to the specified destination"""
        # Create IP packet
        ip_packet = IPPacket(self.ip_address, destination_ip, protocol, data)
        
        # Get next hop MAC address
        next_hop_mac = self.get_next_hop(destination_ip)
        
        # Encapsulate in Ethernet frame and send
        self.send_frame(next_hop_mac, ip_packet.encode())
        print(f"Node {self.mac_address} sent IP packet to {hex(destination_ip)}")
    
    def send_ping(self, destination_ip):
        """Send a ping packet to the specified IP address"""
        self.send_ip_packet(
            destination_ip,
            0,  # Protocol 0 for ping
            f"PING from {self.mac_address}"
        )
        print(f"Node {self.mac_address} sent ping to {hex(destination_ip)}")

    def process_node_mac(self, mac_address):
        """Convert MAC address to port number"""
        if mac_address[-2] == 'R':
        
            port = Node.BASE_PORT + 3 + int(mac_address[-1])
        else:
            port = Node.BASE_PORT + int(mac_address[-1])
        return port

    def listen_for_frames(self):
        """Listen for incoming Ethernet frames"""
        while self.is_running:
            try:
                conn, addr = self.sock.accept()
                with conn:
                    raw_data = conn.recv(2 + 2 + 1 + Node.MAX_DATA_LENGTH)
                    if not raw_data:
                        continue  # Connection closed or no data
                    frame = raw_data.decode('utf-8')
                    self.process_frame(frame)
            except OSError:
                # This can happen if the socket is closed while waiting for accept()
                if self.is_running:
                    print(f"Node {self.mac_address} socket accept() error.")
                break
            except Exception as e:
                print("Error in listen_for_frames:")
                traceback.print_exc()

    def process_frame(self, frame):
        """Process received Ethernet frame and handle encapsulated IP packets"""
        if len(frame) < 5:
            print(f"Node {self.mac_address} received invalid frame: {frame}")
            return

        source = frame[0:2]
        destination = frame[2:4]
        data_length = ord(frame[4:5])
        data = frame[5:5 + data_length] # This is the IP packet in bytes

        if destination == self.mac_address:
            print(f"Node {self.mac_address} received data from {source}: {data}")

            try:
                # If data is a string, convert to bytes
                if isinstance(data, str):
                    data = data.encode('utf-8')
                    
                # Decode IP packet
                ip_packet = IPPacket.decode(data)
                
                # Process if packet is for this node
                if ip_packet.destination == self.ip_address:
                    print(f"Node {self.mac_address} received IP packet from {hex(ip_packet.source)}")
                    
                    # Handle ping protocol
                    if ip_packet.protocol == 0:  # Ping protocol
                        print(f"Received ping: {ip_packet.data}")
                        # Send ping reply
                        self.send_ip_packet(
                            ip_packet.source,
                            0,  # Ping protocol
                            f"PING reply from {self.mac_address}"
                        )
                
            except Exception as e:
                print(f"Error processing IP packet: {e}")
                traceback.print_exc()
        else:
            print(f"Node {self.mac_address} dropped frame from {source} intended for {destination}")

    def shutdown(self):
        """Cleanly shutdown the node"""
        self.is_running = False
        try:
            self.sock.close()
        except Exception as e:
            print(f"Error closing socket on port {self.port}: {e}")

        # Join the listening thread to ensure it finishes
        if self.listen_thread.is_alive():
            self.listen_thread.join()

