import queue
from models.node import Node
from models.arp_packet import ARPPacket
from models.ip_packet import IPPacket


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
                    f"Node {self.mac_address} received Ethernet frame from poisoned {source_mac}"
                )
                # Try to parse as IP packet
                try:
                    ip_packet = IPPacket.decode(data)
                    self.process_spoofed_packet(ip_packet, source_mac)
                except Exception:
                    if isinstance(data, bytes):
                        print(
                            f"  Data (bytes): {' '.join([f'{b:02X}' for b in data[:min(20, len(data))]])}"
                        )
                    else:
                        print(f"  Data: {data}")

            elif destination_mac == self.mac_address:
                print(
                    f"Node {self.mac_address} received Ethernet frame from {source_mac}"
                )

                # Check if it's an ARP packet (starts with 'ARP')
                if isinstance(data, bytes) and data.startswith(b"ARP"):
                    try:
                        # Convert bytes to string for ARP packet
                        arp_data = data.decode("utf-8")
                        arp_packet = ARPPacket.decode(arp_data)
                        print(f"  Received ARP packet: {arp_packet}")
                        self.process_arp_packet(arp_packet)
                    except ValueError as e:
                        print(f"  Error decoding ARP packet: {e}")
                elif isinstance(data, str) and data.startswith("ARP"):
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
                        super().add_ip_packet_to_queue(ip_packet)
                    except Exception as e:
                        print(f"  Failed to decode IP packet: {e}")
                        if isinstance(data, bytes):
                            print(
                                f"  Data (bytes): {' '.join([f'{b:02X}' for b in data[:min(20, len(data))]])}"
                            )
                        else:
                            print(f"  Data: {data}")

            else:
                print(
                    f"Node {self.mac_address} dropped frame from {source_mac} intended for {destination_mac}"
                )

        except Exception as e:
            print(f"Error processing frame: {frame} - {e}")
            import traceback

            traceback.print_exc()

    def process_spoofed_packet(self, ip_packet: IPPacket, source_mac):
        # Check for node field from the original implementation
        if ip_packet.node is not None:

            if isinstance(ip_packet.node, bytes):
                try:
                    ip_packet.node = int(ip_packet.node.decode("utf-8"))
                except ValueError:
                    ip_packet.node = int.from_bytes(ip_packet.node, byteorder="big")

            print(f"  Node Sampled: {hex(ip_packet.node)}")

        # Print the IP packet details
        print(f"  Intercepted IP Packet: {ip_packet}")

        # Forward the packet to the original destination
        # Find the original destination IP address
        destination_ip = self.poison_table[source_mac]
        self.send_ip_packet(destination_ip, ip_packet.protocol, ip_packet.encode())

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
