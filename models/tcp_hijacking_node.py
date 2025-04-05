from models.sniffing_node import SniffingNode
from models.ip_packet import IPPacket
from models.tcp_packet import TCPPacket
import time


class TCPSessionTracker:
    """
    Enhanced class for tracking TCP sessions with improved hijacking capabilities
    """

    def __init__(self, src_ip, src_port, dst_ip, dst_port, session_id):
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_seq = 0
        self.src_ack = 0
        self.dst_seq = 0
        self.dst_ack = 0
        self.state = "TRACKING"  # TRACKING, HIJACKING, HIJACKED
        self.last_activity = time.time()
        self.packets_count = 0
        self.data_exchanged = []  # Store data exchanged in this session
        self.ip_map = {src_ip: dst_ip, dst_ip: src_ip}  # Map each IP to its peer
        self.port_map = {src_ip: src_port, dst_ip: dst_port}  # Map each IP to its port

    def update_stats(self, is_client_to_server, data=""):
        """Update session statistics"""
        self.last_activity = time.time()
        self.packets_count += 1

        if data:
            direction = "→" if is_client_to_server else "←"
            source = (
                f"0x{self.src_ip:02X}:{self.src_port}"
                if is_client_to_server
                else f"0x{self.dst_ip:02X}:{self.dst_port}"
            )
            self.data_exchanged.append(f"{source} {direction} {data}")

    def __str__(self):
        return (
            f"Session {self.session_id}: 0x{self.src_ip:02X}:{self.src_port} <-> 0x{self.dst_ip:02X}:{self.dst_port} "
            f"STATE={self.state}, PACKETS={self.packets_count}"
        )


class TCPHijackingNode(SniffingNode):
    """
    An enhanced node that can perform TCP session hijacking with automatic tracking
    and integration with IP spoofing capabilities
    """

    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)

        # Track TCP sessions - dict with auto-incrementing IDs
        self.tracked_sessions = {}
        self.next_session_id = 1

        # Flag for auto-tracking sessions
        self.auto_track_sessions = False

        # Store spoofed IP (for hijacking)
        self.spoofed_ip = None

        # Register enhanced hijacking commands
        self.register_enhanced_hijacking_commands()

    def register_enhanced_hijacking_commands(self):
        """Register commands for enhanced TCP session hijacking"""

        @self.command("auto_track", "<on/off> - Automatically track all TCP sessions")
        def cmd_auto_track(self, args):
            if not args:
                print("Invalid input. Usage: auto_track <on/off>")
                return

            if args[0].lower() == "on":
                if self.auto_track_sessions:
                    print("Auto-tracking already enabled.")
                else:
                    self.auto_track_sessions = True
                    # Enable promiscuous mode if not already enabled
                    if not self.promiscuous_mode:
                        self.promiscuous_mode = True
                        print("Promiscuous mode enabled for auto-tracking")
                    print("Auto-tracking of TCP sessions enabled")
            elif args[0].lower() == "off":
                if not self.auto_track_sessions:
                    print("Auto-tracking already disabled.")
                else:
                    self.auto_track_sessions = False
                    print("Auto-tracking of TCP sessions disabled")
            else:
                print("Invalid option. Use 'on' or 'off'.")

        @self.command("sessions", "- Show tracked TCP sessions")
        def cmd_sessions(self, args):
            if not self.tracked_sessions:
                print("No TCP sessions being tracked")
                return

            print("Tracked TCP Sessions:")
            for session_id, session in self.tracked_sessions.items():
                print(
                    f"  #{session_id}: 0x{session.src_ip:02X}:{session.src_port} <-> 0x{session.dst_ip:02X}:{session.dst_port}"
                )
                print(f"     State: {session.state}, Packets: {session.packets_count}")
                print(f"     Sequence: SRC={session.src_seq}, DST={session.dst_seq}")
                print(
                    f"     Acknowledgement: SRC_ACK={session.src_ack}, DST_ACK={session.dst_ack}"
                )
                print(f"     Last activity: {time.ctime(session.last_activity)}")

        @self.command(
            "session_data", "<session_id> - Show data exchanged in a TCP session"
        )
        def cmd_session_data(self, args):
            if not args:
                print("Invalid input. Usage: session_data <session_id>")
                return

            try:
                session_id = int(args[0])
                if session_id not in self.tracked_sessions:
                    print(
                        f"Session #{session_id} not found. Use 'sessions' to see available sessions."
                    )
                    return

                session = self.tracked_sessions[session_id]
                if not session.data_exchanged:
                    print(f"No data has been exchanged in session #{session_id}")
                    return

                print(f"Data exchanged in session #{session_id}:")
                for i, data in enumerate(session.data_exchanged):
                    print(f"  {i+1}. {data}")

            except ValueError:
                print("Invalid session ID. Please enter a valid number.")

        @self.command(
            "hijack",
            "<session_id> as <ip_hex> <message> - Hijack session by spoofing as given IP",
        )
        def cmd_hijack(self, args):
            if len(args) < 3 or args[1].lower() != "as":
                print("Invalid input. Usage: hijack <session_id> as <ip_hex> <message>")
                return

            try:
                session_id = int(args[0])
                spoof_ip = int(args[2], 16)
                message = " ".join(args[3:])

                if session_id not in self.tracked_sessions:
                    print(
                        f"Session #{session_id} not found. Use 'sessions' to see available sessions."
                    )
                    return

                session = self.tracked_sessions[session_id]

                # Verify the IP is part of the session
                if spoof_ip != session.src_ip and spoof_ip != session.dst_ip:
                    print(f"Error: IP 0x{spoof_ip:02X} is not part of this session")
                    return

                # Get the target IP automatically using the ip_map
                target_ip = session.ip_map[spoof_ip]

                # Hijack by sending data in the specified direction
                self.hijack_session(session, spoof_ip, target_ip, message)

            except ValueError as e:
                print(f"Error: {e}")

        @self.command(
            "continue",
            "<session_id> <message> - Continue hijacked session with another message",
        )
        def cmd_continue(self, args):
            if len(args) < 2:
                print("Invalid input. Usage: continue <session_id> <message>")
                return

            try:
                session_id = int(args[0])
                message = " ".join(args[1:])

                if session_id not in self.tracked_sessions:
                    print(
                        f"Session #{session_id} not found. Use 'sessions' to see available sessions."
                    )
                    return

                session = self.tracked_sessions[session_id]

                if session.state != "HIJACKED":
                    print(
                        f"Session #{session_id} is not in HIJACKED state. Hijack it first."
                    )
                    return

                if not hasattr(self, "last_spoofed_ip") or not hasattr(
                    self, "last_target_ip"
                ):
                    print(
                        "Error: No previous hijack information available. Please hijack the session first."
                    )
                    return

                # Continue using the last used source and target IPs
                self.continue_session(
                    session, self.last_spoofed_ip, self.last_target_ip, message
                )

            except ValueError as e:
                print(f"Error: {e}")

        @self.command(
            "track",
            "<src_ip> <src_port> <dst_ip> <dst_port> - Manually track a TCP session",
        )
        def cmd_track(self, args):
            if len(args) != 4:
                print(
                    "Invalid input. Usage: track <src_ip> <src_port> <dst_ip> <dst_port>"
                )
                return

            try:
                # Convert hex strings to integers if they start with 0x
                src_ip = (
                    int(args[0], 16) if args[0].startswith("0x") else int(args[0], 16)
                )
                src_port = int(args[1])
                dst_ip = (
                    int(args[2], 16) if args[2].startswith("0x") else int(args[2], 16)
                )
                dst_port = int(args[3])

                # Create a session tracker
                session_id = self.next_session_id
                self.next_session_id += 1

                new_session = TCPSessionTracker(
                    src_ip, src_port, dst_ip, dst_port, session_id
                )

                # Store the session
                self.tracked_sessions[session_id] = new_session

                print(
                    f"Manually tracked TCP session #{session_id}: 0x{src_ip:02X}:{src_port} <-> 0x{dst_ip:02X}:{dst_port}"
                )

            except ValueError as e:
                print(f"Error: {e}")
                print(
                    "Make sure IP addresses are valid hex values (e.g., 2A or 0x2A) and ports are valid integers."
                )

    def process_frame(self, frame):
        """
        Override to automatically track TCP sessions and enhance hijacking capabilities
        """
        # Call the parent method to maintain normal sniffing behavior
        super().process_frame(frame)

        # Only process frames if auto-tracking is enabled and we're in promiscuous mode
        if not self.auto_track_sessions or not self.promiscuous_mode:
            return

        try:
            # Decode the frame
            source_mac, destination_mac, _, data = self.decode_frame(frame)

            # Try to decode as IP packet
            try:
                ip_packet = IPPacket.decode(data)

                # Check if this is TCP traffic (protocol 6)
                if ip_packet.protocol == TCPPacket.PROTOCOL:
                    # Decode the TCP packet
                    tcp_packet = TCPPacket.decode(ip_packet.data)

                    # Process the TCP packet for auto-tracking
                    self.auto_track_tcp_packet(ip_packet, tcp_packet)
            except Exception as e:
                # Not a valid IP or TCP packet - ignore
                pass

        except Exception as e:
            print(f"Error processing frame for TCP tracking: {e}")

    def auto_track_tcp_packet(self, ip_packet, tcp_packet):
        """
        Automatically track TCP packets to monitor all sessions
        """
        source_ip = ip_packet.source_ip
        dest_ip = ip_packet.dest_ip
        source_port = tcp_packet.src_port
        dest_port = tcp_packet.dest_port

        # Log the TCP packet for debugging
        print(
            f"DEBUG: TCP packet detected: 0x{source_ip:02X}:{source_port} -> 0x{dest_ip:02X}:{dest_port} (Flags: {self.get_flag_string(tcp_packet)})"
        )

        # Create session keys in both directions
        forward_key = (source_ip, source_port, dest_ip, dest_port)
        reverse_key = (dest_ip, dest_port, source_ip, source_port)

        # Check if this packet matches an existing session
        found_session = None
        session_id = None

        for sid, session in self.tracked_sessions.items():
            if (
                session.src_ip == source_ip
                and session.src_port == source_port
                and session.dst_ip == dest_ip
                and session.dst_port == dest_port
            ):
                # Forward direction
                found_session = session
                session_id = sid
                is_forward = True
                break
            elif (
                session.src_ip == dest_ip
                and session.src_port == dest_port
                and session.dst_ip == source_ip
                and session.dst_port == source_port
            ):
                # Reverse direction
                found_session = session
                session_id = sid
                is_forward = False
                break

        # If this is a new session, create a new session entry
        if not found_session:
            # Track any TCP packet that has ACK or PSH flags, not just SYN
            if tcp_packet.is_syn() or tcp_packet.is_ack() or tcp_packet.is_psh():
                session_id = self.next_session_id
                self.next_session_id += 1

                # Create new session tracker
                new_session = TCPSessionTracker(
                    source_ip, source_port, dest_ip, dest_port, session_id
                )

                # Store session
                self.tracked_sessions[session_id] = new_session

                # Update sequence numbers
                new_session.src_seq = tcp_packet.seq_num

                # Decode any data if present
                data_content = ""
                if tcp_packet.data:
                    try:
                        if isinstance(tcp_packet.data, bytes):
                            data_content = tcp_packet.data.decode("utf-8")
                        else:
                            data_content = tcp_packet.data
                    except:
                        data_content = f"<binary data of {len(tcp_packet.data)} bytes>"

                # Update session stats
                new_session.update_stats(True, data_content)

                print(
                    f"Auto-tracked new TCP session #{session_id}: 0x{source_ip:02X}:{source_port} <-> 0x{dest_ip:02X}:{dest_port}"
                )

            return

        # Update existing session
        if is_forward:
            # Forward direction packet (client -> server)
            if tcp_packet.seq_num > 0:
                found_session.src_seq = tcp_packet.seq_num
            if tcp_packet.ack_num > 0:
                found_session.src_ack = tcp_packet.ack_num

            # Track data if this is a PSH packet
            data_content = ""
            if tcp_packet.is_psh() and tcp_packet.data:
                try:
                    if isinstance(tcp_packet.data, bytes):
                        data_content = tcp_packet.data.decode("utf-8")
                    else:
                        data_content = tcp_packet.data
                except:
                    data_content = f"<binary data of {len(tcp_packet.data)} bytes>"

            found_session.update_stats(True, data_content)

            # Check for connection termination
            if tcp_packet.is_fin() or tcp_packet.is_rst():
                print(
                    f"TCP session #{session_id} termination initiated by 0x{source_ip:02X}"
                )

        else:
            # Reverse direction packet (server -> client)
            if tcp_packet.seq_num > 0:
                found_session.dst_seq = tcp_packet.seq_num
            if tcp_packet.ack_num > 0:
                found_session.dst_ack = tcp_packet.ack_num

            # Track data if this is a PSH packet
            data_content = ""
            if tcp_packet.is_psh() and tcp_packet.data:
                try:
                    if isinstance(tcp_packet.data, bytes):
                        data_content = tcp_packet.data.decode("utf-8")
                    else:
                        data_content = tcp_packet.data
                except:
                    data_content = f"<binary data of {len(tcp_packet.data)} bytes>"

            found_session.update_stats(False, data_content)

            # Check for connection termination
            if tcp_packet.is_fin() or tcp_packet.is_rst():
                print(
                    f"TCP session #{session_id} termination initiated by 0x{dest_ip:02X}"
                )

    def get_flag_string(self, tcp_packet):
        """Get a readable string of TCP flags"""
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
        return "|".join(flags) if flags else "NONE"

    def hijack_session(self, session, source_ip, target_ip, message):
        """Hijack session by spoofing as source IP and sending to target IP"""
        print(
            f"Hijacking session #{session.session_id}: 0x{source_ip:02X} → 0x{target_ip:02X}"
        )

        # Store which IP we're spoofing as and the target for future continue commands
        self.last_spoofed_ip = source_ip
        self.last_target_ip = target_ip

        # Determine ports and sequence numbers based on direction
        if source_ip == session.src_ip and target_ip == session.dst_ip:
            # Direction: src -> dst
            src_port = session.src_port
            dst_port = session.dst_port
            seq_num = session.src_seq
            ack_num = session.src_ack
        else:
            # Direction: dst -> src
            src_port = session.dst_port
            dst_port = session.src_port
            seq_num = session.dst_seq
            ack_num = session.dst_ack

        # First, send RST to the real endpoint we're impersonating
        print(f"Sending RST to disconnect real host at 0x{source_ip:02X}...")
        self.send_reset_packet(target_ip, dst_port, source_ip, src_port, ack_num)

        # Now send spoofed data
        print(f"Sending spoofed message to 0x{target_ip:02X} as 0x{source_ip:02X}...")
        self.send_spoofed_tcp_data(
            source_ip, src_port, target_ip, dst_port, seq_num, ack_num, message
        )

        # Update session state
        session.state = "HIJACKED"

        # Update sequence number based on direction
        if source_ip == session.src_ip:
            session.src_seq += len(message)
        else:
            session.dst_seq += len(message)

        print(
            f"Session #{session.session_id} hijacked successfully. Use 'continue <session_id> <message>' to send more messages."
        )

    def continue_session(self, session, source_ip, target_ip, message):
        """Continue hijacked session with specified direction"""
        print(
            f"Continuing session #{session.session_id}: 0x{source_ip:02X} → 0x{target_ip:02X}"
        )

        # Determine ports and sequence numbers based on direction
        if source_ip == session.src_ip and target_ip == session.dst_ip:
            # Direction: src -> dst
            src_port = session.src_port
            dst_port = session.dst_port
            seq_num = session.src_seq
            ack_num = session.src_ack
        else:
            # Direction: dst -> src
            src_port = session.dst_port
            dst_port = session.src_port
            seq_num = session.dst_seq
            ack_num = session.dst_ack

        # Send spoofed data
        self.send_spoofed_tcp_data(
            source_ip, src_port, target_ip, dst_port, seq_num, ack_num, message
        )

        # Update sequence number based on direction
        if source_ip == session.src_ip:
            session.src_seq += len(message)
        else:
            session.dst_seq += len(message)

        print(f"Message sent: 0x{source_ip:02X} → 0x{target_ip:02X}")

    def send_spoofed_tcp_data(
        self, src_ip, src_port, dst_ip, dst_port, seq_num, ack_num, data
    ):
        """Send spoofed TCP data packet"""
        # Create TCP packet with PSH and ACK flags
        tcp_packet = TCPPacket(
            src_port=src_port,
            dest_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=TCPPacket.PSH | TCPPacket.ACK,
            data=data,
        )

        # Encode TCP packet
        tcp_data = tcp_packet.encode()

        # Create spoofed IP packet
        ip_packet = IPPacket(
            source_ip=src_ip,  # Spoofed source IP
            dest_ip=dst_ip,
            protocol=TCPPacket.PROTOCOL,
            data=tcp_data,
        )

        # Get destination MAC address
        dest_mac = self.get_mac_for_ip(dst_ip)

        # Send the packet
        if dest_mac:
            ip_data = ip_packet.encode()
            print(
                f"Sending spoofed TCP packet from 0x{src_ip:02X}:{src_port} to 0x{dst_ip:02X}:{dst_port}"
            )
            self.send_frame(dest_mac, ip_data)
        else:
            print(f"No route to host 0x{dst_ip:02X}")

    def send_reset_packet(self, src_ip, src_port, dst_ip, dst_port, seq_num):
        """Send a spoofed RST packet to terminate a connection"""
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

        # Create spoofed IP packet
        ip_packet = IPPacket(
            source_ip=src_ip,  # Spoofed source IP
            dest_ip=dst_ip,
            protocol=TCPPacket.PROTOCOL,
            data=tcp_data,
        )

        # Get destination MAC address
        dest_mac = self.get_mac_for_ip(dst_ip)

        # Send the packet
        if dest_mac:
            ip_data = ip_packet.encode()
            print(
                f"Sending spoofed RST packet from 0x{src_ip:02X}:{src_port} to 0x{dst_ip:02X}:{dst_port}"
            )
            self.send_frame(dest_mac, ip_data)
        else:
            print(f"No route to host 0x{dst_ip:02X}")
