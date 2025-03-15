from models.node import Node
from models.arp_packet import ARPPacket
from models.ip_packet import IPPacket
from models.ping_protocol import PingProtocol


class ARPPoisoningNode(Node):
    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)
        self.register_poisoning_commands()

        # ARP table to store poisoned entries
        # Key: MAC address poisoned, Value: IP address spoofed
        self.poison_table = {}

    def poison_arp(self, target_ip, spoofed_ip):
        """
        Send a fake ARP response to poison the ARP table of other nodes.

        Args:
            target_ip: IP address of the target node to poison (hex value)
            spoofed_ip: IP address to spoof (hex value) - our MAC will be associated with this IP
        """

        # We need to find the MAC address of the target node
        target_mac = None
        for ip, mac in self.arp_table.items():
            if ip == target_ip:
                target_mac = mac
                break

        if target_mac:
            # Create poisoned ARP packet
            arp_packet = ARPPacket(ARPPacket.REPLY, self.mac_address, spoofed_ip)
            packet_data = arp_packet.encode()
            print(arp_packet)

            # Add the poisoned entry to our table
            self.poison_table[target_mac] = spoofed_ip

            print(
                f"Sending spoofed ARP response to {target_mac} claiming {self.mac_address} has IP 0x{spoofed_ip:02X}"
            )

            # Send the fake ARP response in an Ethernet frame to the target
            self.send_frame(target_mac, packet_data)
        else:
            print(f"Unknown target IP 0x{target_ip:02X}. Cannot send ARP spoof.")

    def process_frame(self, frame):
        """Process a received Ethernet frame"""
        try:
            source_mac, destination_mac, _, data = self.decode_frame(frame)

            if source_mac in self.poison_table:
                # source mac is poisoned by us, handle it differently
                print(
                    f"Node {self.mac_address} received Ethernet frame from {source_mac}"
                )
                # Try to parse as IP packet
                try:
                    ip_packet = IPPacket.decode(data)
                    self.process_ip_packet(ip_packet, source_mac)
                except Exception:
                    print(f"  Data: {data}")

            elif destination_mac == self.mac_address:
                print(
                    f"Node {self.mac_address} received Ethernet frame from {source_mac}"
                )

                # Check if it's an ARP packet (starts with 'ARP')
                if data.startswith("ARP"):
                    try:
                        arp_packet = ARPPacket.decode(data)
                        print(f"  Received ARP packet: {arp_packet}")
                        self.process_arp_packet(arp_packet)
                    except ValueError as e:
                        print(f"  Error decoding ARP packet: {e}")
                else:
                    # Try to parse as IP packet
                    try:
                        ip_packet = IPPacket.decode(data)
                        # Use base class method to process IP packet
                        super().process_ip_packet(ip_packet)
                    except Exception as e:
                        print(f"  Data: {data}")

            else:
                print(
                    f"Node {self.mac_address} dropped frame from {source_mac} intended for {destination_mac}"
                )

        except Exception as e:
            print(f"Error processing frame: {frame} - {e}")

    def process_ip_packet(self, ip_packet: IPPacket, source_mac):
        """Process a received IP packet, handling spoofed IP addresses"""

        # Check if this packet is for our spoofed IP
        if ip_packet.dest_ip == self.poison_table[source_mac]:
            print(
                f"  Received IP packet from Spoofed 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
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
            super().process_ip_packet(ip_packet, source_mac)

    def register_poisoning_commands(self):
        @self.command(
            "poison", "<target_ip_hex> <spoofed_ip_hex> - Send spoofed ARP to target "
        )
        def cmd_poison(self: ARPPoisoningNode, args):
            if len(args) != 2:
                print("Invalid input. Usage: poison <target_ip_hex> <spoofed_ip_hex>")
                return

            try:
                target_ip = int(args[0], 16)
                spoofed_ip = int(args[1], 16)

                # Send the spoofed ARP
                self.poison_arp(target_ip, spoofed_ip)
            except ValueError:
                print("Invalid IP addresses. Please enter valid hex values (e.g., 2A)")

        @self.command("poisoned", "- Display list of currently poisoned nodes")
        def cmd_poisoned(self: ARPPoisoningNode, args):
            print("Currently poisoned nodes:")
            if not self.poison_table:
                print("  No nodes currently poisoned")
                return

            for target_mac, spoofed_ip in self.poison_table.items():
                print(
                    f"  Node {target_mac} thinks {self.mac_address} has IP 0x{spoofed_ip:02X}"
                )
