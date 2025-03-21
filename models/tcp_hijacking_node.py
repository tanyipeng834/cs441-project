from models.sniffing_node import SniffingNode
from models.ip_packet import IPPacket
from models.tcp_packet import TCPPacket

# Note: This file uses TCPSessionTracker, which is different from the TCPSession class in tcp_session.py


class TCPSessionTracker:
    """
    Lightweight class for attackers to track TCP sessions they want to monitor/hijack
    This is different from the full TCPSession implementation used by legitimate nodes
    """

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_seq = 0
        self.src_ack = 0
        self.dst_seq = 0
        self.dst_ack = 0
        self.state = "TRACKING"  # TRACKING, HIJACKING, HIJACKED
        self.hijack_data = []  # Data to inject
        self.reset_source = False  # Whether to reset source after hijacking

    def __str__(self):
        return (
            f"TCPSessionTracker[{self.src_ip:02X}:{self.src_port}<->{self.dst_ip:02X}:{self.dst_port}] "
            f"STATE={self.state}, SRC_SEQ={self.src_seq}, DST_SEQ={self.dst_seq}"
        )


class TCPHijackingNode(SniffingNode):
    """
    A node that can perform TCP session hijacking attacks by sniffing traffic,
    tracking sequence numbers, and injecting packets.
    """

    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)

        # Track TCP sessions - dict with key (src_ip, src_port, dst_ip, dst_port)
        self.tracked_sessions = {}

        # Current target session for hijacking
        self.target_session_key = None

        # Register hijacking commands
        self.register_hijacking_commands()

    def register_hijacking_commands(self):
        """Register commands for TCP session hijacking"""

        @self.command(
            "track",
            "<src_ip_hex> <src_port> <dst_ip_hex> <dst_port> - Track a TCP session",
        )
        def cmd_track(self: TCPHijackingNode, args):
            if len(args) != 4:
                print(
                    "Invalid input. Usage: track <src_ip_hex> <src_port> <dst_ip_hex> <dst_port>"
                )
                return

            try:
                src_ip = int(args[0], 16)
                src_port = int(args[1])
                dst_ip = int(args[2], 16)
                dst_port = int(args[3])

                # Create a new session to track
                session = TCPSessionTracker(src_ip, src_port, dst_ip, dst_port)
                session_key = (src_ip, src_port, dst_ip, dst_port)

                # Store the session
                self.tracked_sessions[session_key] = session

                # Make sure promiscuous mode is on
                if not self.promiscuous_mode:
                    self.promiscuous_mode = True
                    print("Promiscuous mode enabled to track session")

                print(
                    f"Tracking TCP session: {src_ip:02X}:{src_port} <-> {dst_ip:02X}:{dst_port}"
                )
            except ValueError:
                print("Invalid IP or port. Please enter valid values.")

        @self.command("sessions", "- Show tracked TCP sessions")
        def cmd_sessions(self: TCPHijackingNode, args):
            if not self.tracked_sessions:
                print("No TCP sessions being tracked")
                return

            print("Tracked TCP Sessions:")
            for i, (key, session) in enumerate(self.tracked_sessions.items()):
                print(
                    f"  {i+1}: 0x{session.src_ip:02X}:{session.src_port} <-> 0x{session.dst_ip:02X}:{session.dst_port}"
                )
                print(f"     State: {session.state}")
                print(f"     Sequence: SRC={session.src_seq}, DST={session.dst_seq}")
                print(
                    f"     Acknowledgement: SRC_ACK={session.src_ack}, DST_ACK={session.dst_ack}"
                )

        @self.command(
            "hijack",
            "<session_index> <message> [reset_source] - Hijack a tracked TCP session, optionally resetting source",
        )
        def cmd_hijack(self: TCPHijackingNode, args):
            if len(args) < 2:
                print(
                    "Invalid input. Usage: hijack <session_index> <message> [reset_source]"
                )
                return

            try:
                session_idx = int(args[0]) - 1  # Convert to 0-based index
                message = (
                    " ".join(args[1:])
                    if len(args) > 2 and args[-1].lower() != "reset_source"
                    else " ".join(args[1:-1] if len(args) > 2 else args[1:])
                )

                # Check if we should reset the source after hijacking
                reset_source = len(args) > 2 and args[-1].lower() == "reset_source"

                # Check if index is valid
                if session_idx < 0 or session_idx >= len(self.tracked_sessions):
                    print(
                        f"Invalid session index. Use 'sessions' to see available sessions."
                    )
                    return

                # Get the session
                session_key = list(self.tracked_sessions.keys())[session_idx]
                session = self.tracked_sessions[session_key]

                # Set as target session
                self.target_session_key = session_key

                # Prepare for hijacking
                session.state = "HIJACKING"
                session.hijack_data = [message]  # Store the message to inject
                session.reset_source = reset_source  # Store whether to reset source

                print(
                    f"Preparing to hijack session from 0x{session.src_ip:02X} to 0x{session.dst_ip:02X}"
                )
                if reset_source:
                    print("Will reset source connection after hijacking")
                print(f"Waiting for the next packet to synchronize sequence numbers...")

            except ValueError:
                print("Invalid session index. Please enter a valid number.")

        @self.command(
            "reset",
            "<session_index> [src|dst|both] - Send RST packet to terminate a session",
        )
        def cmd_reset(self: TCPHijackingNode, args):
            if len(args) < 1:
                print("Invalid input. Usage: reset <session_index> [src|dst|both]")
                return

            try:
                session_idx = int(args[0]) - 1  # Convert to 0-based index

                # Default to both sides if not specified
                reset_target = "both" if len(args) < 2 else args[1].lower()

                # Validate reset target
                if reset_target not in ["src", "dst", "both"]:
                    print("Invalid reset target. Use 'src', 'dst', or 'both'")
                    return

                # Check if index is valid
                if session_idx < 0 or session_idx >= len(self.tracked_sessions):
                    print(
                        f"Invalid session index. Use 'sessions' to see available sessions."
                    )
                    return

                # Get the session
                session_key = list(self.tracked_sessions.keys())[session_idx]
                session = self.tracked_sessions[session_key]

                # Send RST packet based on target
                if reset_target == "both" or reset_target == "dst":
                    self.send_reset_packet(session, True)  # Reset to destination
                    print(f"Sent RST packet to destination 0x{session.dst_ip:02X}")

                if reset_target == "both" or reset_target == "src":
                    self.send_reset_packet(session, False)  # Reset to source
                    print(f"Sent RST packet to source 0x{session.src_ip:02X}")

                # Only remove the session if we reset both sides
                if reset_target == "both":
                    del self.tracked_sessions[session_key]
                    if self.target_session_key == session_key:
                        self.target_session_key = None

                    print(
                        f"Session between 0x{session.src_ip:02X} and 0x{session.dst_ip:02X} removed from tracking"
                    )
                else:
                    print(f"Session still being tracked (only one side was reset)")

            except ValueError:
                print("Invalid session index. Please enter a valid number.")

    def process_frame(self, frame):
        """
        Override to track TCP sessions and perform hijacking
        """
        # Call the parent method to maintain normal sniffing behavior
        super().process_frame(frame)

        try:
            # Only process frames if we're tracking sessions
            if not self.tracked_sessions:
                return

            source_mac, destination_mac, _, data = self.decode_frame(frame)

            # Try to decode as IP packet
            try:
                ip_packet = IPPacket.decode(data)

                # Check if this is TCP traffic (protocol 6)
                if ip_packet.protocol == TCPPacket.PROTOCOL:
                    # Decode the TCP packet
                    tcp_packet = TCPPacket.decode(ip_packet.data)

                    # Process the TCP packet for tracking and hijacking
                    self.track_tcp_packet(ip_packet, tcp_packet)

                    # Check if we need to perform a hijack
                    self.check_for_hijack_opportunity(ip_packet, tcp_packet)

            except Exception as e:
                # Not a valid IP or TCP packet - ignore
                pass

        except Exception as e:
            print(f"Error processing frame for TCP tracking: {e}")

    def track_tcp_packet(self, ip_packet, tcp_packet):
        """
        Track TCP packets to monitor sequence numbers
        """
        source_ip = ip_packet.source_ip
        dest_ip = ip_packet.dest_ip
        source_port = tcp_packet.src_port
        dest_port = tcp_packet.dest_port

        # Check for forward direction matching session
        forward_key = (source_ip, source_port, dest_ip, dest_port)
        # Check for reverse direction matching session
        reverse_key = (dest_ip, dest_port, source_ip, source_port)

        if forward_key in self.tracked_sessions:
            # This is a packet from source to destination
            session = self.tracked_sessions[forward_key]

            # Update sequence numbers
            if tcp_packet.seq_num > 0:
                session.src_seq = tcp_packet.seq_num
            if tcp_packet.ack_num > 0:
                session.src_ack = tcp_packet.ack_num

            # If this is a data packet, track the next expected sequence number
            if len(tcp_packet.data) > 0:
                session.src_seq += len(tcp_packet.data)

            if session.state == "TRACKING":
                print(
                    f"Tracked: SRC->DST Seq={tcp_packet.seq_num}, Ack={tcp_packet.ack_num}, Len={len(tcp_packet.data)}"
                )

        elif reverse_key in self.tracked_sessions:
            # This is a packet from destination to source
            session = self.tracked_sessions[reverse_key]

            # Update sequence numbers
            if tcp_packet.seq_num > 0:
                session.dst_seq = tcp_packet.seq_num
            if tcp_packet.ack_num > 0:
                session.dst_ack = tcp_packet.ack_num

            # If this is a data packet, track the next expected sequence number
            if len(tcp_packet.data) > 0:
                session.dst_seq += len(tcp_packet.data)

            if session.state == "TRACKING":
                print(
                    f"Tracked: DST->SRC Seq={tcp_packet.seq_num}, Ack={tcp_packet.ack_num}, Len={len(tcp_packet.data)}"
                )

    def check_for_hijack_opportunity(self, ip_packet, tcp_packet):
        """
        Check if we should perform a hijack based on the current packet
        """
        if not self.target_session_key or not self.tracked_sessions:
            return

        # Get the target session
        session = self.tracked_sessions[self.target_session_key]

        # Only hijack if we're in HIJACKING state
        if session.state != "HIJACKING":
            return

        source_ip = ip_packet.source_ip
        dest_ip = ip_packet.dest_ip
        source_port = tcp_packet.src_port
        dest_port = tcp_packet.dest_port

        # Prepare to hijack after seeing a packet in the session
        if (
            source_ip == session.src_ip
            and source_port == session.src_port
            and dest_ip == session.dst_ip
            and dest_port == session.dst_port
        ) or (
            source_ip == session.dst_ip
            and source_port == session.dst_port
            and dest_ip == session.src_ip
            and dest_port == session.src_port
        ):

            # We've seen a packet in the session - now hijack it
            if session.hijack_data:
                message = session.hijack_data.pop(0)
                self.inject_hijacked_data(session, message)

                # If that was the last message, change state
                if not session.hijack_data:
                    session.state = "HIJACKED"
                    print("Session hijacked successfully!")

                    # Check if we should reset the source connection
                    if session.reset_source:
                        print("Automatically resetting source connection...")
                        self.send_reset_packet(session, False)  # Reset source only
                        print(
                            f"Sent RST packet to terminate connection for source 0x{session.src_ip:02X}"
                        )

    def inject_hijacked_data(self, session, data):
        """
        Inject data into the TCP session by spoofing packets
        """
        print(f"Injecting hijacked data: {data}")

        # Create TCP packet spoofing the source
        tcp_packet = TCPPacket(
            src_port=session.src_port,
            dest_port=session.dst_port,
            seq_num=session.src_seq,
            ack_num=session.dst_seq,
            flags=TCPPacket.PSH | TCPPacket.ACK,
            data=data,
        )

        # Encode the TCP packet
        tcp_data = tcp_packet.encode()

        # Create IP packet spoofing the source
        ip_packet = IPPacket(
            source_ip=session.src_ip,
            dest_ip=session.dst_ip,
            protocol=TCPPacket.PROTOCOL,
            data=tcp_data,
        )

        # Send the spoofed packet
        packet_data = ip_packet.encode()
        destination_mac = self.get_mac_for_ip(session.dst_ip)

        if destination_mac:
            print(
                f"Sending spoofed TCP packet from 0x{session.src_ip:02X} to 0x{session.dst_ip:02X}"
            )
            self.send_frame(destination_mac, packet_data)

            # Update sequence number for the hijacked connection
            session.src_seq += len(data)
        else:
            print(f"No route to destination 0x{session.dst_ip:02X}")

    def send_reset_packet(self, session, to_destination=True):
        """
        Send a RST packet to terminate a TCP connection
        to_destination: If True, send from source to destination; if False, send from destination to source
        """
        if to_destination:
            src_ip = session.src_ip
            src_port = session.src_port
            dst_ip = session.dst_ip
            dst_port = session.dst_port
            seq_num = session.src_seq
            dest_mac = self.get_mac_for_ip(dst_ip)
        else:
            src_ip = session.dst_ip
            src_port = session.dst_port
            dst_ip = session.src_ip
            dst_port = session.src_port
            seq_num = session.dst_seq
            dest_mac = self.get_mac_for_ip(dst_ip)

        # Create RST packet
        tcp_packet = TCPPacket(
            src_port=src_port,
            dest_port=dst_port,
            seq_num=seq_num,
            ack_num=0,  # Not needed for RST
            flags=TCPPacket.RST,
            data="",
        )

        # Encode the TCP packet
        tcp_data = tcp_packet.encode()

        # Create IP packet
        ip_packet = IPPacket(
            source_ip=src_ip, dest_ip=dst_ip, protocol=TCPPacket.PROTOCOL, data=tcp_data
        )

        # Send the packet
        packet_data = ip_packet.encode()

        if dest_mac:
            print(f"Sending RST packet from 0x{src_ip:02X} to 0x{dst_ip:02X}")
            self.send_frame(dest_mac, packet_data)
        else:
            print(f"No route to host 0x{dst_ip:02X}")
