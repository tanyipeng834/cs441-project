from .ethernet_frame import EthernetFrame
from .ip_packet import IPPacket
from .node import Node


class Router:
    """
    Router with multiple interfaces that can forward IP packets between networks
    """

    def __init__(self, interfaces):
        """
        Initialize router with multiple interfaces

        Args:
            interfaces: List of RouterInterface objects
        """
        self.interfaces = interfaces
        self.routing_table = {}  # Maps destination IP to interface

        # Start all interfaces
        for interface in self.interfaces:
            interface.start(self)

        print(f"Router started with {len(self.interfaces)} interfaces")

    def init_routing_table(self, routing_entries):
        """Initialize the routing table with known routes"""
        self.routing_table = routing_entries

    def get_interface_for_ip(self, ip_address):
        """Find the appropriate interface to route to a given IP"""
        # Check if IP is in a directly connected network
        for interface in self.interfaces:
            if ip_address in interface.network_ips:
                return interface

        # Check routing table for a route
        if ip_address in self.routing_table:
            return self.routing_table[ip_address]

        # No route found
        return None

    def shutdown(self):
        """Shutdown all interfaces"""
        for interface in self.interfaces:
            interface.shutdown()


class RouterInterface(Node):
    """
    A router interface extends the Node class to connect a router to a network
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

    def process_ip_packet(self, ip_packet, source_mac):
        """Process an IP packet received on this interface"""
        print(
            f"Interface {self.mac_address} received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
        )
        print(f"  Protocol: {ip_packet.protocol}, Data: {ip_packet.data}")

        # If the packet is for this interface
        if ip_packet.dest_ip == self.ip_address:
            print(f"  Packet is for this interface {self.mac_address}")

            # Handle ping protocol
            # if ip_packet.protocol == Node.PROTOCOL_PING:
            #     # Check if the data already contains "REPLY:" to prevent infinite loop
            #     if not ip_packet.data.startswith("REPLY:"):
            #         print(f"  Ping request to router, sending reply")
            #         reply_data = f"REPLY: {ip_packet.data}"
            #         # Create reply packet
            #         reply_packet = IPPacket(self.ip_address, ip_packet.source_ip,
            #                             Node.PROTOCOL_PING, reply_data)
            #         # Get destination MAC from our ARP table
            #         if ip_packet.source_ip in self.arp_table:
            #             dest_mac = self.arp_table[ip_packet.source_ip]
            #             # Send reply
            #             self.send_ip_packet(reply_packet, dest_mac)
            #         else:
            #             print(f"  ERROR: No ARP entry for 0x{ip_packet.source_ip:02X}")
            #     else:
            #         print(f"  Ping reply received")
        else:
            # Otherwise let the router handle it
            if self.router:
                # Find outgoing interface from router's routing table
                outgoing_interface = self.router.get_interface_for_ip(ip_packet.dest_ip)

                if outgoing_interface:
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
