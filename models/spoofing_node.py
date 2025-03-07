from models.node import Node
from models.ip_packet import IPPacket
from models.ping_protocol import PingProtocol


class SpoofingNode(Node):
    # Override the send_ip_packet so that we can spoof the ip packet.
    def send_spoof_ip_packet(self, source_ip, destination_ip, protocol, data):
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
            ip_packet = IPPacket(source_ip, destination_ip, protocol, chunk)
            packet_data = ip_packet.encode()

            # Determine the MAC address to send to (either direct or via gateway)
            destination_mac = self.get_mac_for_ip(destination_ip)

            # Send the packet encapsulated in an Ethernet frame
            if destination_mac:
                print(
                    f"Sending IP packet to 0x{destination_ip:02X} via MAC {destination_mac}"
                )
                self.send_frame(destination_mac, packet_data)
            else:
                print(f"No route to host 0x{destination_ip:02X}")


    def send_echo(self, destination_ip, data="PING"):
        """
        Send an Echo Request (ping) to the specified destination IP

        Args:
            destination_ip: IP address of destination (hex value)
            data: Optional data to include in the ping
        """
        # Increment sequence number
        self.ping_sequence = (self.ping_sequence + 1) % 256

        # Create Ping Protocol Echo Request
        

        # Send the Ping Protocol packet encapsulated in an IP packe
        if destination_ip == 0x2A:
            ping_protocol = PingProtocol.create_echo_request(
            identifier=0x2B,  # Use our IP as the identifier
            sequence=self.ping_sequence,
            data=data,
        )
            self.send_spoof_ip_packet(
                source_ip =0x2B,
                destination_ip=destination_ip,
                protocol=PingProtocol.PROTOCOL,
                data = ping_protocol.encode()
            )
        else:
            ping_protocol = PingProtocol.create_echo_request(
            identifier=self.ip_address,  # Use our IP as the identifier
            sequence=self.ping_sequence,
            data=data,
        )
            self.send_ip_packet(
                destination_ip=destination_ip,
                protocol=PingProtocol.PROTOCOL,
                data=ping_protocol.encode(),
            )

        # Store the timestamp for calculating round-trip time
        self.ping_requests[self.ping_sequence] = {
        
            "responded": False,
            "destination": destination_ip,
        }
        print(
            f"Sent Ping Protocol Echo Request to 0x{destination_ip:02X} (seq={self.ping_sequence})"
        )

        return self.ping_sequence
    def run(self):
        """Start an interactive command interface for the node"""
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

                parts = user_input.split(" ", 1)

                if parts[0].lower() == "ping":
                    if len(parts) < 2:
                        print("Invalid input. Usage: ping <ip_hex>")
                        continue

                    try:
                        # Convert hex string to integer
                        dest_ip = int(parts[1], 16)
                        print(dest_ip)

                        # Send Ping
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
                    print("Available commands: ping, arp, help, q")
                    print("Or send raw frame: <destination> <message>")

        except KeyboardInterrupt:
            print("\nKeyboardInterrupt received. Exiting...")
        finally:
            self.shutdown()
            return
