from models.node import Node
from models.ip_packet import IPPacket


class SpoofingNode(Node):
    # Override the send_ip_packet so that we can spoof the ip packet.
    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)
        self.register_spoofing_commands()
        self.spoof = False

    def send_ip_packet(self, destination_ip, protocol, data):
        """
        Send an IP packet by encapsulating it in an Ethernet frame

        Args:
            destination_ip: IP address of destination (hex value)
            protocol: Protocol identifier (e.g., PROTOCOL_PING)
            data: Data to send
        """
        # Create the IP packet
        # Max data size per IP packet
        # Split data into chunks if it's larger than MAX_DATA_SIZE
        MAX_DATA_SIZE = Node.MAX_DATA_LENGTH - 4
        chunks = [
            data[i : i + MAX_DATA_SIZE] for i in range(0, len(data), MAX_DATA_SIZE)
        ]

        for chunk in chunks:
            # Create the IP packet for the chunk
            source_ip = self.ip_address

            if self.spoof:
                # Spoof the source IP address to impersonate Node 3
                source_ip = 0x2B

            ip_packet = IPPacket(source_ip, destination_ip, protocol, chunk)
            packet_data = ip_packet.encode()

            # Determine the MAC address to send to (either direct or via gateway)
            destination_mac = self.get_mac_for_ip(destination_ip)

            # Send the packet encapsulated in an Ethernet frame
            if destination_mac:
                if self.spoof:
                    print(
                        f"Sending Spoofed IP packet to 0x{destination_ip:02X} via MAC {destination_mac}"
                    )
                else:
                    print(
                        f"Sending IP packet to 0x{destination_ip:02X} via MAC {destination_mac}"
                    )

                self.send_frame(destination_mac, packet_data)
            else:
                print(f"No route to host 0x{destination_ip:02X}")

    def register_spoofing_commands(self):
        @self.command("spoof", "<on/off> - Impersonate Node 3 to Ping Node 1 ")
        def spoof_command(self: SpoofingNode, args):
            if not args:
                print("Invalid input. Usage: spoof <on/off>")
                return

            if args[0].lower() == "on":
                if self.spoof:
                    print("Spoofing mode already enabled.")
                else:
                    self.spoof = True
                    print(f"Spoofing Mode enabled")
            elif args[0].lower() == "off":
                if not self.spoof:
                    print("Spoofing Mode already disabled")
                else:
                    self.spoof = False
                    print(f"Spoofing Mode disabled")
