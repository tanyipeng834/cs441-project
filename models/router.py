from .node import Node
import socket
from .ethernet_frame import EthernetFrame
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class Router:
    """
    Router with multiple interfaces that can forward IP packets between networks
    """

    def __init__(self, nodes):
        """
        Initialize router with multiple router nodes

        Args:
            nodes: List of RouterNode objects
        """
        self.nodes = nodes
        self.routing_table = {}  # Maps destination IP to interface
        self.key = None
        self.ipsec = False
        self.auth_tag = None
        

        # Start all nodes
        for node in self.nodes:
            node.start(self)

        print(f"Router started with {len(self.nodes)} interfaces")

    def init_routing_table(self, routing_entries):
        """Initialize the routing table with known routes"""
        self.routing_table = routing_entries

    def get_interface_for_ip(self, ip_address):
        """Find the appropriate interface to route to a given IP"""
        # Check if IP is in a directly connected network
        for node in self.nodes:
            if ip_address in node.network_ips:
                return node

        # Check routing table for a route
        if ip_address in self.routing_table:
            return self.routing_table[ip_address]
        

        # No internal route found, try bgp interface for extenral routing
        return self.routing_table["*"]
    def mutual_key_exchange(self,peer):
        """Establish a shared AES key"""
        seed_value = b"6c58f72c9dbb7adcd330cdb8b97a7261"
        initial_vector = b'\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09'
        print("Exchange public parameters for shared key.")
        
        # Derive AES key using SHA-256 from the seed value
        hash_function = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_function.update(seed_value)
        aes_key = hash_function.finalize()

        # Use AES-CBC mode with a random IV
        self.key = Cipher(algorithms.AES(aes_key), modes.CBC(initial_vector), backend=default_backend())
        self.ipsec = True
        print("Shared symmetric key established.")

        print(f"IPsec Tunnel is established with 0x{peer:02X}")
    
    def encrypt_data(self, text):
        if not self.key:
            raise ValueError("AES key has not been established.")

        
        plaintext = text.encode("utf-8")
        

       
        padding_length = 16 - (len(plaintext) % 16)
        plaintext_padded = plaintext + bytes([padding_length] * padding_length)

        # Encrypt the data
        encryptor = self.key.encryptor()
        ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
        

        # No authentication tag needed here
        return ciphertext

    def decrypt_data(self, ciphertext):
        """Decrypt the data using the AES key in CBC mode."""
        if not self.key:
            raise ValueError("AES key has not been established.")

        decryptor = self.key.decryptor()
        decrypted_padded_text = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        padding_length = decrypted_padded_text[-1]
        decrypted_text = decrypted_padded_text[:-padding_length]

        return decrypted_text.decode("utf-8")




    def shutdown(self):
        """Shutdown all interfaces"""
        for node in self.nodes:
            node.shutdown()


class RouterNode(Node):
    """
    A router node extends the Node class to connect a router to a network
    """

    def __init__(self, mac_address, ip_address, port, network, router=None):
        super().__init__(mac_address, ip_address, port, network)
        self.router = router
        self.network_ips = set()  # Set of IPs in this network

    def start(self, router=None):
        """Start the interface (called by router)"""
        # Set the router if provided
        if router:
            self.router = router

    def init_network_ips(self, network_ips):
        """Set the IPs that belong to this network interface"""
        self.network_ips = set(network_ips)

    def process_ip_packet(self, ip_packet):
        """Process an IP packet received on this interface"""
        print(
            f"Interface {self.mac_address} received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
        )
        print(f"  Protocol: {ip_packet.protocol}, Data: {ip_packet.data}")

        # If the packet is for this interface
        if ip_packet.dest_ip == self.ip_address:
            print(f"  Packet is for this interface {self.mac_address}")
        else:
            # Otherwise let the router handle it
            if self.router:
                # Find outgoing interface from router's routing table
                outgoing_interface = self.router.get_interface_for_ip(ip_packet.dest_ip)

                if outgoing_interface:
                    if isinstance(outgoing_interface,RouterNode):
                        print(
                            f"  Route found: forward via interface {outgoing_interface.mac_address}"
                        )

                        # Find destination MAC using ARP table of outgoing interface
                        if ip_packet.dest_ip in outgoing_interface.arp_table:
                            dest_mac = outgoing_interface.arp_table[ip_packet.dest_ip]
                            print(
                                f"  Forwarding packet to 0x{ip_packet.dest_ip:02X} (MAC: {dest_mac}) via interface {outgoing_interface.mac_address}"
                            )
                            outgoing_interface.send_ip_packet(ip_packet, dest_mac)
                        else:
                            print(
                                f"  ERROR: No ARP entry for 0x{ip_packet.dest_ip:02X} on interface {outgoing_interface.mac_address}"
                            )
                    else:
                        # Instance of bgp node so will send this to bgp node to process
                        outgoing_interface.process_ip_packet(ip_packet)
                else:
                    print(f"  ERROR: No route to 0x{ip_packet.dest_ip:02X}")
            else:
                print(f"  ERROR: Router interface not connected to a router")

    def send_ip_packet(self, ip_packet, dest_mac):
        """Send an IP packet out this interface"""
        print(
            f"Interface {self.mac_address} sending IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
        )
        print(f"  Destination MAC: {dest_mac}")
        packet_data = ip_packet.encode()
        self.send_frame(dest_mac, packet_data)

class BGPRouterNode(Node):
    """
    A router node extends the Node class to connect a router to a network
    """

    def __init__(self, mac_address, ip_address,port,router=None,network=None):
        super().__init__(mac_address, ip_address, port, network=None)
        self.router = router
        self.network_ips = {}  # Set of IPs in this network

    def start(self, router=None):
        """Start the interface (called by router)"""
        # Set the router if provided
        if router:
            self.router = router

    def init_bgp_route(self, network_ips):
        """Set the IPs that belong to this network interface"""
        self.network_ips = network_ips

    def process_ip_packet(self, ip_packet):
        """Process an IP packet received on this interface"""
        print(
            f"Interface {self.mac_address} received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
        )
        print(f"  Protocol: {ip_packet.protocol}, Data: {ip_packet.data}")

        network_prefix = ip_packet.dest_ip & 0XC0
        internal_ip = ip_packet.dest_ip &~0xC0
        
        if network_prefix == self.ip_address:
            print(f"  Packet is for this interface {self.mac_address}")
            if ip_packet.data.startswith("IKE") :
                if self.router:
                    self.router.mutual_key_exchange(ip_packet.source_ip)
                return


            # Otherwise let the router handle it
            if self.router:
                # Find outgoing interface from router's routing table
                outgoing_interface = self.router.get_interface_for_ip(internal_ip)

                if outgoing_interface:
                    print(
                        f"  Route found: forward via interface {outgoing_interface.mac_address}"
                    )
                    # Perform NAT from public ip address to private ip address.
                    
                    ip_packet.dest_ip = internal_ip

                    # Find destination MAC using ARP table of outgoing interface
                    if internal_ip in outgoing_interface.arp_table:
                        dest_mac = outgoing_interface.arp_table[internal_ip]
                        print(
                            f"  Forwarding packet to 0x{internal_ip:02X} (MAC: {dest_mac}) via interface {outgoing_interface.mac_address}"
                        )
                        outgoing_interface.send_ip_packet(ip_packet, dest_mac)
                    else:
                        print(
                            f"  ERROR: No ARP entry for 0x{internal_ip:02X} on interface {outgoing_interface.mac_address}"
                        )
                else:
                    print(f"  ERROR: No route to 0x{internal_ip:02X}")
            else:
                print(f"  ERROR: Router interface not connected to a router")
        else:
           
            port_number, mac_address = self.network_ips[network_prefix]
            
           
            if port_number: 
                self.send_ip_packet(ip_packet,port_number,mac_address)
            else:
                print(f"There is no BGP Route to the Network prefix 0x{network_prefix:02X}")

        

    def send_ip_packet(self, ip_packet, port,mac_address):
        """Send an IP packet out this interface"""
        # Perform NAT from private ip to public ip address.
        if ip_packet.source_ip != self.ip_address:
            ip_packet.source_ip = self.ip_address + ip_packet.source_ip

        print(
            f"Interface {self.mac_address} sending IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
        )
        packet_data = ip_packet.encode()
        self.send_frame(port,packet_data,mac_address)
    def send_frame(self, destination_port, frame_data,mac_address):
        """
        Send an Ethernet frame thorough BGP routing policies 
        """
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((Node.HOST_IP, destination_port))
                frame = EthernetFrame(
                    self.mac_address, mac_address, frame_data
                )
                s.sendall(frame.encode())
        except Exception as e:
            print(
                f"Error sending frame from {self.mac_address} to port {destination_port}: {e}"
            )
