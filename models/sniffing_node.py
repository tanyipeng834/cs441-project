from models.node import Node
from models.ip_packet import IPPacket
from models.ping_protocol import PingProtocol
from models.tcp_packet import TCPPacket


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

        # Register additional commands
        self.register_sniffing_commands()

    def register_sniffing_commands(self):
        """Register commands specific to the sniffing node"""

        @self.command("sniff", "<on/off/show/clear> - Promiscuous mode commands")
        def cmd_sniff(self: SniffingNode, args):
            if not args:
                print("Invalid input. Usage: sniff <on/off>")
                return

            if args[0].lower() == "on":
                if self.promiscuous_mode:
                    print("Promiscuous mode already enabled.")
                else:
                    self.promiscuous_mode = True
                    print(f"Promiscuous mode enabled on {self.mac_address}")
                    # If TCP tracking is available (in TCP Hijacking Node), enable it
                    if hasattr(self, "auto_track_sessions"):
                        self.auto_track_sessions = True
                        print("TCP session tracking automatically enabled")
            elif args[0].lower() == "off":
                if not self.promiscuous_mode:
                    print("Promiscuous mode already disabled.")
                else:
                    self.promiscuous_mode = False
                    print(f"Promiscuous mode disabled on {self.mac_address}")
                    # If TCP tracking is available, disable it
                    if hasattr(self, "auto_track_sessions"):
                        self.auto_track_sessions = False
                        print("TCP session tracking disabled")
            elif args[0].lower() == "show":
                self.display_sniffed_packets()
            elif args[0].lower() == "clear":
                self.sniffed_packets = []
                print("Sniffed packet list cleared.")
            else:
                print("Invalid option. Usage: sniff <on/off/show/clear>.")

    def process_frame(self, frame):
        """
        Override the process_frame method to sniff all frames on the network
        when in promiscuous mode, not just those addressed to this node.
        """
        source_mac, destination_mac, data_length, data = self.decode_frame(frame)

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

                    # Try to decode as TCP if applicable
                    elif ip_packet.protocol == 6:  # TCP protocol
                        try:
                            tcp_packet = TCPPacket.decode(ip_packet.data)
                            sniffed_info["tcp_src_port"] = tcp_packet.src_port
                            sniffed_info["tcp_dst_port"] = tcp_packet.dst_port

                            # Add TCP flags information
                            flags = []
                            if tcp_packet.is_syn():
                                flags.append("SYN")
                            if tcp_packet.is_ack():
                                flags.append("ACK")
                            if tcp_packet.is_fin():
                                flags.append("FIN")
                            if tcp_packet.is_rst():
                                flags.append("RST")
                            if tcp_packet.is_psh():
                                flags.append("PSH")
                            sniffed_info["tcp_flags"] = (
                                "|".join(flags) if flags else "NONE"
                            )

                            # If there's data, try to decode it
                            if tcp_packet.data:
                                try:
                                    if isinstance(tcp_packet.data, bytes):
                                        sniffed_info["tcp_data"] = (
                                            tcp_packet.data.decode("utf-8")
                                        )
                                    else:
                                        sniffed_info["tcp_data"] = str(tcp_packet.data)
                                except:
                                    sniffed_info["tcp_data"] = (
                                        f"<binary data of {len(tcp_packet.data)} bytes>"
                                    )

                            # If we have auto_track_sessions method (from TCP Hijacking Node), call it
                            if (
                                hasattr(self, "auto_track_tcp_packet")
                                and hasattr(self, "auto_track_sessions")
                                and self.auto_track_sessions
                            ):
                                print(
                                    f"Attempting to track TCP packet: {ip_packet.source_ip:02X}:{tcp_packet.src_port} -> {ip_packet.dest_ip:02X}:{tcp_packet.dst_port}"
                                )
                                self.auto_track_tcp_packet(ip_packet, tcp_packet)

                        except Exception as e:
                            sniffed_info["tcp_decode_error"] = str(e)
                except:
                    sniffed_info["raw_text"] = data.decode("utf-8")
                    # If not an IP packet, just store the raw data
                    pass

                self.sniffed_packets.append(sniffed_info)
                print(f"SNIFFED: Frame from {source_mac} to {destination_mac}")
                print(
                    f"  Ethernet Header: [src={source_mac}, dst={destination_mac}, length={data_length}]"
                )

        # Process the frame as normal
        super().process_frame(frame)

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
                    print(f"  Ping Type: {ping_type}")
                    print(f"  Ping Code: {packet['ping_code']}")
                    print(f"  Ping Data: {packet['ping_data']}")

                elif "tcp_src_port" in packet:
                    print(f"  TCP src port: {packet['tcp_src_port']}")
                    print(f"  TCP dst port: {packet['tcp_dst_port']}")
                    print(f"  TCP flags: {packet['tcp_flags']}")
                    if "tcp_data" in packet:
                        print(f"  TCP data: {packet['tcp_data']}")
            else:
                print(f"  Raw Data: {packet['raw_data']}")
        print("\n================================")

    # Method to manually track a TCP session if needed
    def track_tcp_session(self, src_ip, src_port, dst_ip, dst_port):
        """
        Manually track a TCP session (useful when auto-tracking doesn't work)
        """
        # Only available if we have the tracking capability from TCP Hijacking Node
        if hasattr(self, "tracked_sessions") and hasattr(self, "next_session_id"):
            # Convert IPs from hex strings if provided that way
            if isinstance(src_ip, str) and src_ip.startswith("0x"):
                src_ip = int(src_ip, 16)
            if isinstance(dst_ip, str) and dst_ip.startswith("0x"):
                dst_ip = int(dst_ip, 16)

            # Make sure ports are integers
            src_port = int(src_port)
            dst_port = int(dst_port)

            # Create a new session
            from models.tcp_hijacking_node import ImprovedTCPSessionTracker

            session_id = self.next_session_id
            self.next_session_id += 1

            new_session = ImprovedTCPSessionTracker(
                src_ip, src_port, dst_ip, dst_port, session_id
            )

            # Store the session
            self.tracked_sessions[session_id] = new_session

            print(
                f"Manually tracked TCP session #{session_id}: 0x{src_ip:02X}:{src_port} <-> 0x{dst_ip:02X}:{dst_port}"
            )
            return session_id
        else:
            print("TCP session tracking capability not available.")
            return None
