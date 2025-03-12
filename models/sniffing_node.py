from models.node import Node
from models.ip_packet import IPPacket
from models.ping_protocol import PingProtocol


class SniffingNode(Node):
    """
    A node that can sniff all traffic on the network, not just traffic addressed to it.
    This emulates a malicious node in promiscuous mode capturing all frames.
    """

    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)
        # Log to store captured packets
        self.sniffed_packets = []
        self.promiscuous_mode = False
        print(f"Malicious node {mac_address} initialized with sniffing capabilities.")

    def toggle_promiscuous_mode(self):
        """Toggle promiscuous mode on/off"""
        self.promiscuous_mode = not self.promiscuous_mode
        status = "enabled" if self.promiscuous_mode else "disabled"
        print(f"Promiscuous mode {status} on {self.mac_address}")

    def process_frame(self, frame):
        """
        Override the process_frame method to sniff all frames on the network
        when in promiscuous mode, not just those addressed to this node.
        """
        if len(frame) < 5:
            print(f"Node {self.mac_address} received invalid frame: {frame}")
            return

        source_mac = frame[0:2]
        destination_mac = frame[2:4]
        data_length = ord(frame[4:5])
        data = frame[5 : 5 + data_length]

        # In promiscuous mode, capture all frames
        if self.promiscuous_mode:
            # Don't capture frames originating from this node
            if source_mac != self.mac_address:
                # Store the sniffed frame data
                sniffed_info = {
                    "source_mac": source_mac,
                    "destination_mac": destination_mac,
                    "data_length": data_length,
                    "raw_data": data,
                }

                # Try to decode as IP packet for more detailed info
                try:
                    ip_packet = IPPacket.decode(data)
                    sniffed_info["protocol"] = ip_packet.protocol
                    sniffed_info["source_ip"] = f"0x{ip_packet.source_ip:02X}"
                    sniffed_info["dest_ip"] = f"0x{ip_packet.dest_ip:02X}"

                    # Try to decode as ping if applicable
                    if ip_packet.protocol == PingProtocol.PROTOCOL:
                        try:
                            ping_packet = PingProtocol.decode(ip_packet.data)
                            sniffed_info["ping_type"] = ping_packet.ping_type
                            sniffed_info["ping_code"] = ping_packet.code
                            sniffed_info["ping_data"] = ping_packet.data
                        except:
                            sniffed_info["ping_decode_error"] = True
                except:
                    # If not an IP packet, just store the raw data
                    pass

                self.sniffed_packets.append(sniffed_info)
                print(f"SNIFFED: Frame from {source_mac} to {destination_mac}")

        # Process frame normally for frames addressed to this node
        if destination_mac == self.mac_address:
            print(f"Node {self.mac_address} received Ethernet frame from {source_mac}")

            # Check if it contains an IP packet (at least 4 bytes for IP header)
            if len(data) >= 4:
                try:
                    # Try to parse as IP packet
                    ip_packet = IPPacket.decode(data)
                    self.process_ip_packet(ip_packet)
                except:
                    # If it's not an IP packet, just treat as raw data
                    print(f"  Data: {data}")
        else:
            # Frame is not addressed to this node - drop it
            # (even though we might have sniffed it in promiscuous mode)
            if self.promiscuous_mode:
                print(
                    f"Node {self.mac_address} sniffed but dropped frame from {source_mac} intended for {destination_mac}"
                )
            else:
                print(
                    f"Node {self.mac_address} dropped frame from {source_mac} intended for {destination_mac}"
                )

    def display_sniffed_packets(self):
        """Display all sniffed packets"""
        if not self.sniffed_packets:
            print("No packets have been sniffed yet.")
            return

        print(f"\n=== Sniffed Packets ({len(self.sniffed_packets)}) ===")
        for i, packet in enumerate(self.sniffed_packets):
            print(f"\nPacket #{i+1}:")
            print(f"  Source MAC: {packet['source_mac']}")
            print(f"  Destination MAC: {packet['destination_mac']}")

            if "source_ip" in packet:
                print(f"  Source IP: {packet['source_ip']}")
                print(f"  Destination IP: {packet['dest_ip']}")
                print(f"  Protocol: {packet['protocol']}")

                if "ping_type" in packet:
                    ping_types = {
                        0: "ECHO_REPLY",
                        3: "DEST_UNREACHABLE",
                        8: "ECHO_REQUEST",
                        11: "TIME_EXCEEDED",
                    }
                    ping_type = ping_types.get(
                        packet["ping_type"], str(packet["ping_type"])
                    )
                    print(f"  ping Type: {ping_type}")
                    print(f"  ping Code: {packet['ping_code']}")
                    print(f"  ping Data: {packet['ping_data']}")
            else:
                print(f"  Raw Data: {packet['raw_data']}")
        print("\n================================")

    def display_help(self):
        """Display help information for the command interface with sniffing commands"""
        super().display_help()
        print("\nSniffing commands:")
        print("  sniff on/off - Toggle promiscuous mode (sniffing) on/off")
        print("  sniffed - Display all sniffed packets")
        print("  clear - Clear the list of sniffed packets")

    def run(self):
        """Override run method to add sniffing commands"""
        self.display_help()

        try:
            while True:
                user_input = input(f"{self.mac_address}>> ").strip()
                if user_input.lower() == "q":
                    print("Exiting...")
                    break
                if not user_input:
                    continue
                if user_input.lower() == "help":
                    self.display_help()
                    continue

                # Handle sniffing commands
                if user_input.lower() == "sniff on":
                    (
                        self.toggle_promiscuous_mode()
                        if not self.promiscuous_mode
                        else print("Promiscuous mode already enabled")
                    )
                    continue
                elif user_input.lower() == "sniff off":
                    (
                        self.toggle_promiscuous_mode()
                        if self.promiscuous_mode
                        else print("Promiscuous mode already disabled")
                    )
                    continue
                elif user_input.lower() == "sniffed":
                    self.display_sniffed_packets()
                    continue
                elif user_input.lower() == "clear":
                    self.sniffed_packets = []
                    print("Sniffed packet list cleared.")
                    continue

                # Handle original commands
                parts = user_input.split(" ", 1)

                if parts[0].lower() == "ping":
                    if len(parts) < 2:
                        print("Invalid input. Usage: ping <ip_hex>")
                        continue

                    ping_parts = parts[1].split(" ", 1)
                    if len(ping_parts) < 2:
                        print("Invalid input. Usage: ping <ip_hex> <message>")
                        continue

                    try:
                        # Convert hex string to integer
                        dest_ip = int(ping_parts[0], 16)
                        message = ping_parts[1]

                        # Send ping packet
                        self.send_ip_packet(dest_ip, IPPacket.PROTOCOL, message)
                        print(f"Ping sent to 0x{dest_ip:02X} with message: {message}")
                    except ValueError:
                        print(
                            "Invalid IP address. Please enter a valid hex value (e.g., 2A)"
                        )

                elif parts[0].lower() == "pingping":
                    if len(parts) < 2:
                        print("Invalid input. Usage: pingping <ip_hex>")
                        continue

                    try:
                        # Convert hex string to integer
                        dest_ip = int(parts[1], 16)

                        # Send ping
                        self.send_echo(dest_ip)
                    except ValueError:
                        print(
                            "Invalid IP address. Please enter a valid hex value (e.g., 2A)"
                        )

                elif parts[0].lower() == "arp":
                    print("ARP Table:")
                    for ip, mac in self.arp_table.items():
                        print(f"  0x{ip:02X} -> {mac}")

                elif parts[0] in self.VALID_DESTINATION:
                    # Original frame-sending format
                    if len(parts) != 2:
                        print(
                            "Invalid input. Please provide both destination and data."
                        )
                        continue

                    destination = parts[0]
                    data = parts[1]

                    self.send_frame(destination, data)
                    print(f"Ethernet frame sent to {destination} with data: {data}")

                else:
                    print("Invalid command or destination.")
                    print(
                        "Available commands: ping, pingping, arp, sniff on/off, sniffed, clear, help, q"
                    )
                    print("Or send raw frame: <destination> <message>")

        except KeyboardInterrupt:
            print("\nKeyboardInterrupt received. Exiting...")
        finally:
            self.shutdown()
            return
