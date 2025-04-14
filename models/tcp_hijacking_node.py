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
                message = " ".join(args[3:]) if len(args) > 3 else ""

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

                # Enable promiscuous mode if it's not already on
                if not self.promiscuous_mode:
                    print("Enabling promiscuous mode to capture all network traffic")
                    self.promiscuous_mode = True

                # Perform ARP poisoning first - using your existing method
                print(
                    f"Performing ARP poisoning: telling 0x{target_ip:02X} that 0x{spoof_ip:02X} has our MAC address"
                )
                self.poison_arp(target_ip, spoof_ip)

                # Now proceed with the hijacking
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

        # Add a new command to show both TCP sessions and poisoned ARP entries
        @self.command(
            "hijack_status",
            "- Show hijacking status including sessions and poisoned nodes",
        )
        def cmd_hijack_status(self, args):
            """Show comprehensive status of hijacking operations"""
            # Show TCP sessions first
            if not self.tracked_sessions:
                print("No TCP sessions being tracked")
            else:
                print("\n=== Tracked TCP Sessions ===")
                for session_id, session in self.tracked_sessions.items():
                    print(
                        f"  #{session_id}: 0x{session.src_ip:02X}:{session.src_port} <-> 0x{session.dst_ip:02X}:{session.dst_port}"
                    )
                    print(
                        f"     State: {session.state}, Packets: {session.packets_count}"
                    )
                    if session.state == "HIJACKED":
                        print(f"     ** HIJACKED **")

            # Show poisoned ARP entries
            if hasattr(self, "poison_table") and self.poison_table:
                print("\n=== Poisoned ARP Entries ===")
                for target_mac, spoofed_ip in self.poison_table.items():
                    print(
                        f"  Node {target_mac} thinks {self.mac_address} has IP 0x{spoofed_ip:02X}"
                    )
            elif hasattr(self, "poison_table"):
                print("\nNo ARP entries currently poisoned")
            else:
                print("\nARP poisoning capability not fully integrated")

        @self.command("end_hijack", "<session_id> - End a hijacked session")
        def cmd_end_hijack(self, args):
            """End a hijacked session and clean up resources"""
            if not args:
                print("Invalid input. Usage: end_hijack <session_id>")
                return

            try:
                session_id = int(args[0])

                if session_id not in self.tracked_sessions:
                    print(f"Session #{session_id} not found.")
                    return

                session = self.tracked_sessions[session_id]

                if session.state != "HIJACKED":
                    print(f"Session #{session_id} is not currently hijacked.")
                    return

                # Send FIN packets to both ends to cleanly terminate the session
                if hasattr(self, "last_spoofed_ip") and hasattr(self, "last_target_ip"):
                    # Direction we were hijacking
                    source_ip = self.last_spoofed_ip
                    target_ip = self.last_target_ip

                    # Determine ports based on which side we were impersonating
                    if source_ip == session.src_ip:
                        src_port = session.src_port
                        dst_port = session.dst_port
                        seq_num = session.src_seq
                    else:
                        src_port = session.dst_port
                        dst_port = session.src_port
                        seq_num = session.dst_seq

                    # Create FIN packet to cleanly terminate
                    from models.tcp_packet import TCPPacket

                    tcp_packet = TCPPacket(
                        src_port=src_port,
                        dest_port=dst_port,
                        seq_num=seq_num,
                        ack_num=0,
                        flags=TCPPacket.FIN,
                        data="",
                    )

                    # Encode and send the packet
                    tcp_data = tcp_packet.encode()
                    from models.ip_packet import IPPacket

                    ip_packet = IPPacket(
                        source_ip=source_ip,
                        dest_ip=target_ip,
                        protocol=TCPPacket.PROTOCOL,
                        data=tcp_data,
                    )

                    # Get MAC and send
                    dest_mac = self.get_mac_for_ip(target_ip)
                    if dest_mac:
                        print(f"Sending FIN packet to gracefully terminate session...")
                        self.send_frame(dest_mac, ip_packet.encode())

                # Remove session from tracking
                print(f"Removing hijacked session #{session_id}")
                del self.tracked_sessions[session_id]

            except ValueError as e:
                print(f"Error: {e}")

        @self.command("reset", "- Reset all hijacking and poisoning state")
        def cmd_reset(self, args):
            """Reset all hijacking state and poisoning tables"""
            # Clear tracked sessions
            session_count = len(self.tracked_sessions)
            self.tracked_sessions = {}
            self.next_session_id = 1

            # Clear poison table if it exists
            poison_count = 0
            if hasattr(self, "poison_table"):
                poison_count = len(self.poison_table)
                self.poison_table = {}

            # Reset other state
            if hasattr(self, "last_spoofed_ip"):
                del self.last_spoofed_ip
            if hasattr(self, "last_target_ip"):
                del self.last_target_ip

            print(
                f"Reset complete: Cleared {session_count} tracked sessions and {poison_count} poisoned ARP entries."
            )
            print("Node is ready for new hijacking operations.")

        # Add this combined command to the TCPHijackingNode class

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
            if len(data) >= 4 and data[3] == len(data[4:]):
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
        """
        Hijack session by spoofing as source IP and sending to target IP

        This version ensures RST packets only affect the intended recipient
        """
        print(
            f"Hijacking session #{session.session_id}: 0x{source_ip:02X} → 0x{target_ip:02X}"
        )

        # Store which IP we're spoofing as and the target for future continue commands
        self.last_spoofed_ip = source_ip
        self.last_target_ip = target_ip

        # Determine ports and sequence numbers based on direction
        if source_ip == session.src_ip and target_ip == session.dst_ip:
            # Direction: client -> server (impersonating client)
            src_port = session.src_port
            dst_port = session.dst_port
            seq_num = session.src_seq
            ack_num = session.src_ack

            # If impersonating client, send RST from server -> client to disconnect client
            print(
                f"Sending targeted RST to disconnect real client at 0x{source_ip:02X}..."
            )
            self.send_reset_packet(
                target_ip, dst_port, source_ip, src_port, session.dst_seq
            )
        else:
            # Direction: server -> client (impersonating server)
            src_port = session.dst_port
            dst_port = session.src_port
            seq_num = session.dst_seq
            ack_num = session.dst_ack

            # If impersonating server, send RST from client -> server to disconnect server
            print(
                f"Sending targeted RST to disconnect real server at 0x{source_ip:02X}..."
            )
            self.send_reset_packet(
                target_ip, dst_port, source_ip, src_port, session.src_seq
            )

        # Add a small delay to ensure the RST packet is processed
        time.sleep(0.5)

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

    # Enhanced version of send_reset_packet method
    def send_reset_packet(self, src_ip, src_port, dst_ip, dst_port, seq_num):
        """
        Send a carefully crafted RST packet to terminate ONLY the target's connection

        The key issue is ensuring the RST packet is only processed by the intended target.
        By crafting an Ethernet frame with a specific destination MAC, we ensure the RST
        packet is only delivered to the intended node.

        Args:
            src_ip: Source IP (spoofed) - will appear to be from this IP
            src_port: Source port
            dst_ip: Destination IP - the node we want to disconnect
            dst_port: Destination port
            seq_num: Sequence number for the RST packet - use expected sequence number
        """
        # Get the MAC address of ONLY the target we want to disconnect
        target_mac = None
        for ip, mac in self.arp_table.items():
            if ip == dst_ip:
                target_mac = mac
                break

        if not target_mac:
            print(f"Error: Could not find MAC address for IP 0x{dst_ip:02X}")
            return False

        print(f"Sending targeted RST packet to: {target_mac} (0x{dst_ip:02X})")

        # Create a carefully crafted RST packet

        tcp_packet = TCPPacket(
            src_port=src_port,
            dest_port=dst_port,
            seq_num=seq_num,  # Use current sequence number to ensure it's accepted
            ack_num=0,  # Not needed for RST
            flags=TCPPacket.RST,
            data="",
        )

        # Encode TCP packet
        tcp_data = tcp_packet.encode()

        # Create IP packet with spoofed source IP
        ip_packet = IPPacket(
            source_ip=src_ip,  # This appears to be from the peer (spoofed)
            dest_ip=dst_ip,  # The node we want to disconnect
            protocol=TCPPacket.PROTOCOL,
            data=tcp_data,
        )

        # Encode the IP packet
        ip_data = ip_packet.encode()

        # Now we directly create and send the Ethernet frame
        # This ensures the packet ONLY goes to the intended target
        print(
            f"Sending targeted Ethernet frame to {target_mac} with spoofed IP 0x{src_ip:02X}"
        )
        self.send_frame(target_mac, ip_data)

        return True

    def poison_arp(self, target_ip, spoofed_ip):
        """
        Send a fake ARP response to poison the ARP table of other nodes.
        This method adapts the poisoning functionality from ARPPoisoningNode.

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
            from models.arp_packet import ARPPacket

            arp_packet = ARPPacket(ARPPacket.REPLY, self.mac_address, spoofed_ip)
            packet_data = arp_packet.encode()
            print(arp_packet)

            # Keep track of poisoned entries (create the table if it doesn't exist)
            if not hasattr(self, "poison_table"):
                self.poison_table = {}

            # Add the poisoned entry to our table
            self.poison_table[target_mac] = spoofed_ip

            print(
                f"Sending spoofed ARP response to {target_mac} claiming {self.mac_address} has IP 0x{spoofed_ip:02X}"
            )

            # Send the fake ARP response in an Ethernet frame to the target
            self.send_frame(target_mac, packet_data)
        else:
            print(f"Unknown target IP 0x{target_ip:02X}. Cannot send ARP spoof.")

    def process_ip_packet(self, ip_packet):
        """
        Override the process_ip_packet method to accept packets meant for IPs we're spoofing
        """
        # Accept packets for our real IP address
        if ip_packet.dest_ip == self.ip_address or ip_packet.dest_ip == 0xFF:
            # Process normally using parent class method
            super().process_ip_packet(ip_packet)
            return

        # Check if we're hijacking any sessions and are spoofing an IP address
        if (
            hasattr(self, "last_spoofed_ip")
            and ip_packet.dest_ip == self.last_spoofed_ip
        ):
            print(
                f"  Received IP packet addressed to spoofed IP 0x{ip_packet.dest_ip:02X} (we're impersonating this node)"
            )
            print(
                f"  From: 0x{ip_packet.source_ip:02X}, Protocol: {ip_packet.protocol}"
            )

            # Handle different protocols
            if ip_packet.protocol == 0:  # Ping protocol
                self.handle_ping_protocol(ip_packet)
            elif ip_packet.protocol == 6:  # TCP protocol
                try:
                    from models.tcp_packet import TCPPacket

                    tcp_packet = TCPPacket.decode(ip_packet.data)
                    print(f"  Received TCP packet for hijacked session: {tcp_packet}")

                    # Extract and display any data
                    if tcp_packet.is_psh() and tcp_packet.data:
                        data_content = ""
                        if isinstance(tcp_packet.data, bytes):
                            try:
                                data_content = tcp_packet.data.decode("utf-8")
                            except UnicodeDecodeError:
                                data_content = (
                                    f"<binary data of {len(tcp_packet.data)} bytes>"
                                )
                        else:
                            data_content = tcp_packet.data

                        print(
                            f'\nReceived message in hijacked session from 0x{ip_packet.source_ip:02X}: "{data_content}"\n'
                        )

                        # Send ACK
                        self.send_tcp_ack(
                            ip_packet.source_ip, tcp_packet, ip_packet.dest_ip
                        )

                except Exception as e:
                    print(f"  Error processing TCP packet: {e}")
            else:
                print(f"  Unknown protocol: {ip_packet.protocol}")
        else:
            # Default behavior for other packets
            print(f"  Dropped IP packet intended for 0x{ip_packet.dest_ip:02X}")

    # 2. Add a helper method to send TCP ACKs for received data
    def send_tcp_ack(self, dest_ip, tcp_packet, source_ip):
        """Send an ACK for TCP data with proper sequence numbers"""

        # Calculate next sequence number based on data length
        data_len = len(tcp_packet.data) if tcp_packet.data else 0
        next_seq = tcp_packet.seq_num + data_len
        if (
            tcp_packet.is_syn() or tcp_packet.is_fin()
        ):  # SYN and FIN consume a sequence number
            next_seq += 1

        # Find the session to get the correct sequence number for our ACK
        our_seq = 0
        for session_id, session in self.tracked_sessions.items():
            if (session.src_ip == dest_ip and session.dst_ip == source_ip) or (
                session.dst_ip == dest_ip and session.src_ip == source_ip
            ):
                # Use the sequence number from our side of the connection
                if source_ip == session.src_ip:
                    our_seq = session.src_seq
                else:
                    our_seq = session.dst_seq
                break

        # Create ACK packet
        ack_packet = TCPPacket(
            src_port=tcp_packet.dest_port,
            dest_port=tcp_packet.src_port,
            seq_num=our_seq,  # Our current sequence number
            ack_num=next_seq,  # What we've received from them plus data length
            flags=TCPPacket.ACK,
            data="",
        )

        # Encode and send
        print(
            f"  Sending ACK for received data in hijacked session (SEQ={our_seq}, ACK={next_seq})"
        )

        # Create IP packet
        ip_packet = IPPacket(
            source_ip=source_ip,
            dest_ip=dest_ip,
            protocol=TCPPacket.PROTOCOL,
            data=ack_packet.encode(),
        )

        # Get MAC and send
        dest_mac = self.get_mac_for_ip(dest_ip)
        if dest_mac:
            self.send_frame(dest_mac, ip_packet.encode())
        else:
            print(f"No route to host 0x{dest_ip:02X}")
