from .node import Node
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .ipsec_packet import IPSecPacket
from .ip_packet import IPPacket
import hmac
import hashlib
from .arp_packet import ARPPacket
import random


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
        self.cipher = None
        self.ipsec = False
        self.auth_tag = None
        self.ipsec_mode = None
        self.peer = None
        self.aes_key = None

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
        return None

    def mutual_key_exchange(self, mode, peer):
        """Establish a shared AES key"""
        seed_value = b"6c58f72c9dbb7adcd330cdb8b97a7261"
        initial_vector = (
            b"\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09"
        )
        print("Exchange public parameters for shared key.")
        self.ipsec_mode = mode
        self.peer = peer

        # Derive AES key using SHA-256 from the seed value
        hash_function = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_function.update(seed_value)
        self.aes_key = hash_function.finalize()

        # Use AES-CBC mode with a random IV
        self.cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.CBC(initial_vector),
            backend=default_backend(),
        )
        self.ipsec = True
        print("Shared symmetric key established.")

        print(f"IPsec Tunnel is established with 0x{self.peer:02X}")

    def kill_tunnel(self):
        """Establish a shared AES key"""
        self.cipher = None
        self.aes_key = None
        self.ipsec = False
        print(f"IPsec Tunnel is demolished with 0x{self.peer:02x}")
        self.peer = None
        self.ipsec_mode = None

        return

    def encrypt_data(self, text):
        if not self.cipher:
            raise ValueError("AES key has not been established.")

        plaintext = text

        padding_length = 16 - (len(plaintext) % 16)
        plaintext_padded = plaintext + bytes([padding_length] * padding_length)

        # Encrypt the data
        encryptor = self.cipher.encryptor()
        ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

        # No authentication tag needed here
        return ciphertext

    def decrypt_data(self, ciphertext):
        """Decrypt the data using the AES key in CBC mode."""
        if not self.cipher:
            raise ValueError("AES key has not been established.")

        decryptor = self.cipher.decryptor()
        decrypted_padded_text = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        padding_length = decrypted_padded_text[-1]
        decrypted_text = decrypted_padded_text[:-padding_length]

        return decrypted_text.decode("utf-8")

    def compute_mac(self, data):
        if not self.aes_key:
            raise ValueError("AES key has not been established.")

        # The AES key used for HMAC, we assume it's already derived
        key = self.aes_key

        if isinstance(data, str):
            data = data.encode("utf-8")
        mac = hmac.new(key, data, hashlib.sha256).digest()

        return mac

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
        # differenitate between ip_pacet and ipsec packet

        if self.router.ipsec:

            if isinstance(ip_packet, IPSecPacket):
                # This means that this is a ipsec packet.

                ipSecPacket = ip_packet
                print(ipSecPacket)

                mac = self.router.compute_mac(ipSecPacket.ip_packet)

                if mac != ipSecPacket.mac:
                    print(
                        "Integrity Check Failed. MAC Computed does not match the one in the packet. Discarding IP Packet."
                    )
                    return
                print("Integrity Check passed ! MAC matches the one in the ip packet.")
                if ipSecPacket.mode == 1:

                    ip_packet = IPPacket.decode(
                        self.router.decrypt_data(ipSecPacket.ip_packet)
                    )
                    print("IP packet Decrypted with mutual key exchanged.")
                    print(ip_packet)

                else:

                    ip_packet = IPPacket.decode(ipSecPacket.ip_packet.decode("utf-8"))
                    print(ip_packet)

        # If ipsec is not enabled, it means the packet would be an ip packet.
        if isinstance(ip_packet.source_ip, bytes) and isinstance(
            ip_packet.dest_ip, bytes
        ):
            source_ip = ip_packet.source_ip.decode("utf-8")
            dest_ip = ip_packet.dest_ip.decode("utf-8")
            print(
                f"Interface {self.mac_address} received IP packet from 0x{source_ip:02X} to 0x{dest_ip:02X}"
            )

        else:

            print(
                f"Interface {self.mac_address} received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
            )

        if ip_packet.dest_ip == self.ip_address:

            print(f"  Packet is for this interface {self.mac_address}")
            if isinstance(ip_packet.data, bytes) and ip_packet.data.startswith(b"IKE"):
                if self.router:

                    if not self.router.ipsec:
                        if ip_packet.data[-1] == 49:
                            mode = 1
                        else:
                            mode = 0
                        self.router.mutual_key_exchange(mode, ip_packet.source_ip)

                    else:
                        self.router.kill_tunnel()
                        return

        elif ip_packet.dest_ip == 0xFF:
            print(f"  Broadcast packet received on interface {self.mac_address}")

            # Forward to all nodes in this interface's network
            for node_mac in self.network:
                if node_mac != self.mac_address:  # Don't send back to self
                    print(f"  Forwarding broadcast to network node {node_mac}")
                    self.send_frame(node_mac, ip_packet.encode())

        else:
            # Otherwise let the router handle it
            p = 0.5  # Threshold for node sampling (could be set dynamically)
            x = random.random()  # Random number between 0 and 1

            # add the ip address for node sampling

            if x < p:
                ip_packet.node = self.ip_address
                print("Node has been added to ip packet")

            if self.router:
                # Find outgoing interface from router's routing table
                outgoing_interface = self.router.get_interface_for_ip(ip_packet.dest_ip)

                if outgoing_interface:
                    if isinstance(outgoing_interface, RouterNode):
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

        # Encrypt when it is from different network
        if self.router.ipsec and ((self.ip_address & 0xF0) >> 4) != (
            (ip_packet.dest_ip & 0xF0) >> 4
        ):

            if self.router.ipsec_mode == 1:
                # Change this to the encrypted packet if it is ESP
                packet_data = self.router.encrypt_data(packet_data)
                print("Encrypting IP Packet")
            # MAC have to be calculated if it is ESP or AH
            mac = self.router.compute_mac(packet_data)
            print("Add HMAC for integrity check")
            ipSecPacket = IPSecPacket(
                self.ip_address,
                self.router.peer,
                self.router.ipsec_mode,
                packet_data,
                mac,
            )
            packet_data = ipSecPacket.encode()
        self.send_frame(dest_mac, packet_data)

    def process_frame(self, frame):
        """Process a received Ethernet frame"""
        

        source_mac, destination_mac, data_length, data = self.decode_frame(frame)
        
        if isinstance(source_mac, bytes):

            source_mac = frame[0:2].decode("utf-8")

        if isinstance(destination_mac, bytes):

            destination_mac = frame[2:4].decode("utf-8")

            if not isinstance(bytes, frame[5:]):
                data = frame[5:]
            else:

                data = frame[5:].decode("utf-8")
           

        if destination_mac == self.mac_address or destination_mac == "FF":
            print(f"Node {self.mac_address} received Ethernet frame from {source_mac}")

            # Check if it's an ARP packet (starts with 'ARP')

            if not isinstance(data, bytes) and data.startswith("ARP"):
                try:
                    arp_packet = ARPPacket.decode(data)
                    print(f"  Received ARP packet: {arp_packet}")
                    self.process_arp_packet(arp_packet)
                except ValueError as e:
                    print(f"  Error decoding ARP packet: {e}")
            else:
                # Try to parse as IP packet

                if data[0] == 0xA0:
                    self.process_ip_packet(
                        IPSecPacket.decode(data)
                    )  # Process as IPSec packet
                else:
                    # Otherwise, treat it as a regular IP packet
                    try:
                        
                        ip_packet = IPPacket.decode(data)
                        print(ip_packet)
                        
                        self.process_ip_packet(
                            ip_packet
                        )  # Process as regular IP packet
                    except Exception as e:
                        print("Error processing IP packet:")
                        import traceback
                        traceback.print_exc()
        else:
            print(
                f"Node {self.mac_address} dropped frame from {source_mac} intended for {destination_mac}"
            )
            print(
                f"  Ethernet Header: [src={source_mac}, dst={destination_mac}, length={data_length}]"
            )
