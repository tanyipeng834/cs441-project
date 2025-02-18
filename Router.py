from Node import Node
from IPPacket import IPPacket, IP_ADDRESSES

class RouterInterface(Node):
    """A router interface extends Node with routing capabilities"""
    def __init__(self, mac_address, port, network):
        super().__init__(mac_address, port, network)
        # Initialize routing table for this interface
        self.routing_table = {
            0x1A: 'N1',  # Node1
            0x2A: 'N2',  # Node2
            0x2B: 'N3',  # Node3
            0x11: 'R1',  # Router interface 1
            0x21: 'R2'   # Router interface 2
        }

class Router:
    """
    Router class that manages multiple interfaces and handles packet forwarding
    """
    def __init__(self):
        # Router interfaces will be initialized in Main.py
        self.interfaces = {}
        
    def add_interface(self, interface_name, interface):
        """Add a new interface to the router"""
        self.interfaces[interface_name] = interface

    def get_interface(self, interface_name):
        """Get a specific interface by name"""
        return self.interfaces.get(interface_name)

    def forward_packet(self, incoming_interface, ip_packet):
        """
        Forward an IP packet to the appropriate interface
        Returns: (next_hop_mac, outgoing_interface) or None if no route found
        """
        destination_ip = ip_packet.destination
        
        # Determine which interface should handle this packet
        for interface in self.interfaces.values():
            if destination_ip in interface.routing_table:
                next_hop_mac = interface.routing_table[destination_ip]
                return next_hop_mac, interface
        
        return None

    def process_packet(self, incoming_interface_name, packet_data):
        """
        Process a packet received on one of the router's interfaces
        """
        try:
            # Decode the IP packet
            ip_packet = IPPacket.decode(packet_data)
            
            # Get the incoming interface
            incoming_interface = self.interfaces[incoming_interface_name]
            
            # Find the next hop and outgoing interface
            result = self.forward_packet(incoming_interface, ip_packet)
            
            if result:
                next_hop_mac, outgoing_interface = result
                print(f"Router forwarding packet from {hex(ip_packet.source)} to {hex(ip_packet.destination)} via {outgoing_interface.mac_address}")
                # Forward the packet
                outgoing_interface.send_frame(next_hop_mac, packet_data)
            else:
                print(f"Router could not find route for destination {hex(ip_packet.destination)}")
                
        except Exception as e:
            print(f"Error processing packet in router: {e}")