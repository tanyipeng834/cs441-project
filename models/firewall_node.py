from models.node import Node
from models.ip_packet import IPPacket
from models.ping_protocol import PingProtocol
from models.tcp_packet import TCPPacket


class FirewallNode(Node):
    """
    A node that implmenets a firewall to block certain IP addresses
    """

    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)
        self.dropped_ips = set()
        self.dropped_packets = []

        # Register additional commands
        self.register_firewall_commands()

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
            self.dropped_packets.append(ip_packet)
            print(f"  Dropped IP packet from IP 0x{ip_packet.source_ip:02X}")

        elif ip_packet.dest_ip == self.ip_address or ip_packet.dest_ip == 0xFF:
            print(
                f"  Received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
            )
            print(f"  Protocol: {ip_packet.protocol}, Data length: {ip_packet.length}")

            # Handle different protocols
            if ip_packet.protocol == PingProtocol.PROTOCOL:
                self.handle_ping_protocol(ip_packet)
            elif ip_packet.protocol == 6:  # TCP protocol
                try:
                    tcp_packet = TCPPacket.decode(ip_packet.data)
                    print(f"  Received TCP packet: {tcp_packet}")
                    self.process_tcp_packet(tcp_packet, ip_packet.source_ip)
                except Exception as e:
                    print(f"  Error processing TCP packet: {e}")
                    print(f"  TCP data: {ip_packet.data}")
            else:
                print(
                    f"  Unknown protocol: {ip_packet.protocol}, Data: {ip_packet.data}"
                )
        else:
            print(f"  Dropped IP packet intended for 0x{ip_packet.dest_ip:02X}")

    def register_firewall_commands(self):
        """Register firewall commands"""

        @self.command("drop", "<ip>/show/table - Drop all packets from an IP address")
        def cmd_drop(self: FirewallNode, args):
            if not args:
                print("Invalid input. Usage: drop <ip>/table/show")
                return

            if args[0] == "table":
                print("Dropped IP addresses:")
                for ip in self.dropped_ips:
                    print(f"  0x{ip:02X}")
                return

            if args[0] == "show":
                print("Dropped Packets:")
                for packet in self.dropped_packets:
                    print(f"  {packet}")
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
