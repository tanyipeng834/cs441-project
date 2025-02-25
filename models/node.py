import socket
import threading
import sys
import traceback
from .ethernet_frame import EthernetFrame
from .ip_packet import IPPacket

class Node:
    MAX_DATA_LENGTH = 256
    HOST_IP = "127.0.0.1"
    BASE_PORT = 50000
    VALID_DESTINATION = ["N1", "N2", "N3", "R1", "R2"]
    
    # Protocol constant
    PROTOCOL_PING = 0

    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        self.mac_address = mac_address
        self.ip_address = ip_address  # IP address in hex (e.g., 0x1A)
        self.port = port
        self.network = network
        self.default_gateway = default_gateway  # MAC address of default gateway
        
        # ARP Table: Maps IP addresses to MAC addresses
        self.arp_table = {}
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Allow reusing the address to avoid
            # "Address already in use" in quick restarts
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((Node.HOST_IP, self.port))
            self.sock.listen(1)
        except socket.error as e:
            print(f"Error starting node on port {self.port}: {e}")
            sys.exit(1)

        print(f"Node {self.mac_address} (IP: 0x{self.ip_address:02X}) started on port {self.port}.")

        # Flag to control the listening loop
        self.is_running = True

        # Start a non-daemon thread to listen for incoming frames
        self.listen_thread = threading.Thread(target=self.listen_for_frames)
        self.listen_thread.start()

    def init_arp_table(self, arp_entries):
        """Initialize the ARP table with known IP-to-MAC mappings"""
        self.arp_table = arp_entries

    def get_mac_for_ip(self, ip_address):
        """Look up MAC address for a given IP"""
        if ip_address in self.arp_table:
            return self.arp_table[ip_address]
        return self.default_gateway  # If not in ARP table, use default gateway

    def send_frame(self, destination_mac, data):
        """
        Send an Ethernet frame to all other nodes in the same network (Ethernet broadcast).
        Each node that receives it decides if it is the intended recipient or not.
        
        Args:
            destination_mac: MAC address of destination (2 characters)
            data: data to send in the frame
        """
        for node_mac in self.network:
            if node_mac != self.mac_address:  # Skip sending to itself
                destination_port = self.process_node_mac(node_mac)
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((Node.HOST_IP, destination_port))
                        frame = EthernetFrame(self.mac_address, destination_mac, data)
                        s.sendall(frame.encode())
                except Exception as e:
                    print(
                        f"Error sending frame from {self.mac_address} to port {destination_port}: {e}"
                    )

    def send_ip_packet(self, destination_ip, protocol, data):
        """
        Send an IP packet by encapsulating it in an Ethernet frame
        
        Args:
            destination_ip: IP address of destination (hex value)
            protocol: Protocol identifier (e.g., PROTOCOL_PING)
            data: Data to send
        """
        # Create the IP packet
        ip_packet = IPPacket(self.ip_address, destination_ip, protocol, data)
        packet_data = ip_packet.encode()
        
        # Determine the MAC address to send to (either direct or via gateway)
        destination_mac = self.get_mac_for_ip(destination_ip)
        
        if destination_mac:
            print(f"Sending IP packet to 0x{destination_ip:02X} via MAC {destination_mac}")
            self.send_frame(destination_mac, packet_data)
        else:
            print(f"No route to host 0x{destination_ip:02X}")

    def process_node_mac(self, mac_address):
        """Convert MAC address to port number"""
        if mac_address[-2] == "R":
            # Router ports are BASE_PORT + 3 + router_number
            port = Node.BASE_PORT + 3 + int(mac_address[-1])
        else:
            # Node ports are BASE_PORT + node_number
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
                    frame = raw_data.decode("utf-8")
                    self.process_frame(frame)
            except OSError:
                # This can happen if the socket is closed while waiting for accept()
                if self.is_running:
                    print(f"Node {self.mac_address} socket accept() error.")
                break
            except Exception:
                print("Error in listen_for_frames:")
                traceback.print_exc()

    def process_frame(self, frame):
        """Process a received Ethernet frame"""
        if len(frame) < 5:
            print(f"Node {self.mac_address} received invalid frame: {frame}")
            return

        source_mac = frame[0:2]
        destination_mac = frame[2:4]
        data_length = ord(frame[4:5])
        data = frame[5:5 + data_length]

        if destination_mac == self.mac_address:
            print(f"Node {self.mac_address} received Ethernet frame from {source_mac}")
            
            # Check if it contains an IP packet (at least 4 bytes for IP header)
            if len(data) >= 4:
                try:
                    # Try to parse as IP packet
                    ip_packet = IPPacket.decode(data)
                    self.process_ip_packet(ip_packet, source_mac)
                except:
                    # If it's not an IP packet, just treat as raw data
                    print(f"  Data: {data}")
        else:
            print(
                f"Node {self.mac_address} dropped frame from {source_mac} intended for {destination_mac}"
            )

    def process_ip_packet(self, ip_packet, source_mac):
        """Process a received IP packet"""
        # No ARP table updates for this simplified project
        
        if ip_packet.dest_ip == self.ip_address:
            print(f"  Received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}")
            print(f"  Protocol: {ip_packet.protocol}, Data: {ip_packet.data}")
            
            # Handle ping protocol
            # if ip_packet.protocol == Node.PROTOCOL_PING:
            #     # Check if the data already contains "REPLY:" to prevent infinite loop
            #     if not ip_packet.data.startswith("REPLY:"):
            #         print(f"  Ping request received, sending reply")
            #         reply_data = f"REPLY: {ip_packet.data}"
            #         self.send_ip_packet(ip_packet.source_ip, Node.PROTOCOL_PING, reply_data)
            #     else:
            #         print(f"  Ping reply received")
        else:
            print(f"  Dropped IP packet intended for 0x{ip_packet.dest_ip:02X}")

    def shutdown(self):
        """Shutdown the node and close connections"""
        self.is_running = False
        try:
            self.sock.close()
        except Exception as e:
            print(f"Error closing socket on port {self.port}: {e}")

        # Join the listening thread to ensure it finishes
        if self.listen_thread.is_alive():
            self.listen_thread.join()