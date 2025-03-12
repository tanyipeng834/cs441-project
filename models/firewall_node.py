from models.node import Node
from models.ip_packet import IPPacket
from models.ping_protocol import PingProtocol


class FirewallNode(Node):
    """
    A node that implmenets a firewall to block certain IP addresses
    """

    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)
        self.dropped_ips = set()

        # Register additional commands
        self.register_firewall_commands()

        print(f"Firewall node {mac_address} initialised.")

    def drop_ip(self, ip_address):
        """
        Drop all IP packets from an IP address
        """
        self.dropped_ips.add(ip_address)

    def accept_ip(self, ip_address):
        """
        Accept IP packets from an IP address
        """
        self.dropped_ips.discard(ip_address)

    def process_ip_packet(self, ip_packet: IPPacket):
        """Override the process_ip_packet method to filter packets"""

        if ip_packet.source_ip in self.dropped_ips:
            print(f"  Dropped IP packet from IP 0x{ip_packet.source_ip:02X}")

        elif ip_packet.dest_ip == self.ip_address:
            print(
                f"  Received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
            )
            print(f"  Protocol: {ip_packet.protocol}, Data length: {ip_packet.length}")

            # Handle different protocols
            if ip_packet.protocol == PingProtocol.PROTOCOL:
                self.handle_ping_protocol(ip_packet)
            else:
                print(
                    f"  Unknown protocol: {ip_packet.protocol}, Data: {ip_packet.data}"
                )
        else:
            print(f"  Dropped IP packet intended for 0x{ip_packet.dest_ip:02X}")

    def register_firewall_commands(self):
        """Register firewall commands"""

        @self.command("drop", "<ip> - Drop all packets from an IP address")
        def cmd_drop(self: FirewallNode, args):
            if not args:
                print("Invalid input. Usage: drop <ip>")
                return

            ip = int(args[0], 16)
            self.drop_ip(ip)
            print(f"IP address 0x{ip:02X} dropped.")

        @self.command("accept", "<ip> - Accept packets from an IP address")
        def cmd_accept(self: FirewallNode, args):
            if not args:
                print("Invalid input. Usage: accept <ip>")
                return

            ip = int(args[0], 16)
            self.accept_ip(ip)
            print(f"IP address 0x{ip:02X} accepted.")

        @self.command("showtable", "- Show the list of dropped IP addresses")
        def cmd_showtable(self: FirewallNode, args):
            print("Dropped IP addresses:")
            for ip in self.dropped_ips:
                print(f"  0x{ip:02X}")
