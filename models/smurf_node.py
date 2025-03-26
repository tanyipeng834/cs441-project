import time
from models.node import Node
from models.ip_packet import IPPacket
from models.ping_protocol import PingProtocol


class SmurfNode(Node):
    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)
        self.register_smurf_commands()

    def send_spoofed_echo(self, spoofed_source_ip, destination_ip, data="SMURF"):
        """
        Send an Echo Request (ping) with a spoofed source IP address

        Args:
            spoofed_source_ip: Spoofed source IP (the victim's IP)
            destination_ip: Destination IP (broadcast address)
            data: Optional data to include in the ping
        """
        # Increment sequence number
        self.ping_sequence = (self.ping_sequence + 1) % 256

        # Create Ping Protocol Echo Request
        ping_protocol = PingProtocol.create_echo_request(
            identifier=spoofed_source_ip,  # Use spoofed IP as the identifier
            sequence=self.ping_sequence,
            data=data,
        )

        # Create IP packet with spoofed source IP
        ip_packet = IPPacket(
            source_ip=spoofed_source_ip,  # Spoofed source IP
            dest_ip=destination_ip,
            protocol=PingProtocol.PROTOCOL,
            data=ping_protocol.encode(),
        )
        packet_data = ip_packet.encode()

        # Determine the MAC address to send to (either direct or via gateway)
        destination_mac = self.get_mac_for_ip(destination_ip)

        # Send the packet encapsulated in an Ethernet frame
        if destination_mac:
            print(
                f"Sending spoofed IP packet from 0x{spoofed_source_ip:02X} to 0x{destination_ip:02X} via MAC {destination_mac}"
            )
            self.send_frame(destination_mac, packet_data)
            print(
                f"Sent spoofed Echo Request (victim=0x{spoofed_source_ip:02X}, broadcast=0x{destination_ip:02X}, seq={self.ping_sequence})"
            )
        else:
            print(f"No route to host 0x{destination_ip:02X}")

        return self.ping_sequence  # Return sequence for tracking

    def register_smurf_commands(self):
        @self.command(
            "smurf",
            "<victim_ip_hex> <broadcast_ip_hex> [-c count] - Send Smurf attack",
            True,
        )
        def cmd_smurf(self: SmurfNode, args):
            if len(args) < 2:
                print(
                    "Invalid input. Usage: smurf <victim_ip_hex> <broadcast_ip_hex> [-c count]"
                )
                return

            try:
                # Parse arguments
                victim_ip = int(args[0], 16)
                broadcast_ip = int(args[1], 16)
                count = 1  # Default to one ping

                # Check if -c flag is present
                if len(args) >= 4 and args[2] == "-c":
                    try:
                        count = int(args[3])
                        if count < 1:
                            print("Count must be a positive number")
                            return
                    except ValueError:
                        print("Invalid count value. Must be a positive integer.")
                        return

                print(
                    f"Initiating Smurf attack: spoofing source IP 0x{victim_ip:02X} to broadcast 0x{broadcast_ip:02X}"
                )

                # Send the spoofed ping(s)
                for i in range(count):
                    if count > 1:
                        print(f"Sending spoofed ping {i+1}/{count}...")
                        time.sleep(0.1)
                    self.send_spoofed_echo(victim_ip, broadcast_ip)

            except ValueError:
                print("Invalid IP address. Please enter valid hex values (e.g., 2A)")
