class TCPSession:
    """
    Maintains state for a TCP session between two endpoints
    """

    # Connection states
    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RECEIVED = 3
    ESTABLISHED = 4
    FIN_WAIT = 5
    CLOSING = 6
    LAST_ACK = 7
    TIME_WAIT = 8

    def __init__(self, local_ip, local_port, remote_ip=None, remote_port=None):
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port

        # Sequence and acknowledgment numbers
        self.seq_num = 0  # Our sequence number
        self.ack_num = 0  # Last acknowledged sequence number
        self.next_seq = 0  # Expected next sequence number from remote

        # Connection state
        self.state = TCPSession.CLOSED

        # Data buffers
        self.received_data = []
        self.send_buffer = []

        # Connection established flag to prevent multiple notifications
        self.connection_established_notified = False

    def set_remote_endpoint(self, remote_ip, remote_port):
        """Set the remote endpoint details"""
        self.remote_ip = remote_ip
        self.remote_port = remote_port

    def start_passive_open(self):
        """Start listening for connections"""
        self.state = TCPSession.LISTEN
        print(f"TCP session in LISTEN state on port {self.local_port}")

    def start_active_open(self):
        """Initiate a connection to the remote endpoint"""
        if not self.remote_ip or not self.remote_port:
            raise ValueError("Remote endpoint not set")

        # Generate initial sequence number (simplified)
        self.seq_num = 1000  # In a real implementation, this would be randomized

        # Update state
        self.state = TCPSession.SYN_SENT

        # Return a SYN packet
        from models.tcp_packet import TCPPacket

        return TCPPacket(
            src_port=self.local_port,
            dest_port=self.remote_port,
            seq_num=self.seq_num,
            ack_num=0,  # No acknowledgment yet
            flags=TCPPacket.SYN,
            data="",
        )

    def handle_packet(self, tcp_packet, source_ip):
        """
        Process an incoming TCP packet and update session state
        Returns a response packet if needed, otherwise None
        """
        from models.tcp_packet import TCPPacket

        # Create a debug string for the packet
        flags_str = []
        if tcp_packet.is_syn():
            flags_str.append("SYN")
        if tcp_packet.is_ack():
            flags_str.append("ACK")
        if tcp_packet.is_fin():
            flags_str.append("FIN")
        if tcp_packet.is_rst():
            flags_str.append("RST")
        if tcp_packet.is_psh():
            flags_str.append("PSH")
        flags = "|".join(flags_str) if flags_str else "NONE"

        # Check if this is from our expected remote endpoint
        if self.state != TCPSession.LISTEN and self.remote_ip != source_ip:
            print(
                f"TCP SESSION DEBUG: Unexpected packet from 0x{source_ip:02X}, expected 0x{self.remote_ip:02X}"
            )
            # Send RST packet for unexpected connection
            return TCPPacket(
                src_port=self.local_port,
                dest_port=tcp_packet.src_port,
                seq_num=self.seq_num,
                ack_num=0,
                flags=TCPPacket.RST,
                data=b"",
            )

        # Handle based on current state
        if self.state == TCPSession.LISTEN:
            if tcp_packet.is_syn():
                # Received SYN, move to SYN_RECEIVED
                self.remote_ip = source_ip
                self.remote_port = tcp_packet.src_port
                self.next_seq = tcp_packet.seq_num + 1
                self.seq_num = 2000  # Our initial sequence number (simplified)
                self.state = TCPSession.SYN_RECEIVED

                # Send SYN-ACK
                return TCPPacket(
                    src_port=self.local_port,
                    dest_port=self.remote_port,
                    seq_num=self.seq_num,
                    ack_num=self.next_seq,
                    flags=TCPPacket.SYN | TCPPacket.ACK,
                    data=b"",
                )

        elif self.state == TCPSession.SYN_SENT:
            if tcp_packet.is_syn() and tcp_packet.is_ack():
                # Received SYN-ACK, move to ESTABLISHED
                # Check that they're acknowledging our SYN
                if tcp_packet.ack_num == self.seq_num + 1:

                    self.seq_num = tcp_packet.ack_num  # Update our sequence number
                    self.next_seq = tcp_packet.seq_num + 1  # Their sequence number + 1
                    self.state = TCPSession.ESTABLISHED

                    # Print connection established message for client side
                    if not self.connection_established_notified:
                        print(
                            f"\nConnection established with 0x{self.remote_ip:02X}:{self.remote_port}\n"
                        )
                        self.connection_established_notified = True

                    # Send ACK to complete the handshake
                    return TCPPacket(
                        src_port=self.local_port,
                        dest_port=self.remote_port,
                        seq_num=self.seq_num,
                        ack_num=self.next_seq,
                        flags=TCPPacket.ACK,
                        data=b"",
                    )
                else:
                    print(
                        f"TCP SESSION DEBUG: Invalid ACK in SYN-ACK: {tcp_packet.ack_num}, expected {self.seq_num+1}"
                    )

        elif self.state == TCPSession.SYN_RECEIVED:
            if tcp_packet.is_ack():
                # Final ACK received, connection established
                self.seq_num += (
                    1  # Add this line to increment sequence number after SYN-ACK
                )
                self.state = TCPSession.ESTABLISHED

                # Print connection established message for server side
                if not self.connection_established_notified:
                    print(
                        f"\nConnection established with 0x{self.remote_ip:02X}:{self.remote_port}\n"
                    )
                    self.connection_established_notified = True

                return None

        elif self.state == TCPSession.ESTABLISHED:
            # Handle data transfer
            # Handle data transfer
            if tcp_packet.is_rst():
                # Connection reset by peer
                print(
                    f"\nConnection reset by 0x{source_ip:02X}:{tcp_packet.src_port}\n"
                )
                self.state = TCPSession.CLOSED
                # IMPORTANT: Instead of returning None, we'll return a special flag
                # to indicate that this connection should be closed but not affect other connections
                return "CLOSE_ONLY_THIS_END"

            elif tcp_packet.is_fin():
                # Remote wants to close connection
                self.state = TCPSession.LAST_ACK
                self.next_seq = tcp_packet.seq_num + 1

                # Send FIN-ACK
                return TCPPacket(
                    src_port=self.local_port,
                    dest_port=self.remote_port,
                    seq_num=self.seq_num,
                    ack_num=self.next_seq,
                    flags=TCPPacket.FIN | TCPPacket.ACK,
                    data=b"",
                )

            elif len(tcp_packet.data) > 0:
                # Data packet
                data_len = len(tcp_packet.data)

                if tcp_packet.seq_num == self.next_seq:
                    # In-sequence data
                    # Convert data to string if it's bytes
                    if isinstance(tcp_packet.data, bytes):
                        try:
                            data_str = tcp_packet.data.decode("utf-8")
                            self.received_data.append(data_str)
                        except UnicodeDecodeError:
                            # If we can't decode as UTF-8, store raw bytes
                            self.received_data.append(tcp_packet.data)
                    else:
                        self.received_data.append(tcp_packet.data)

                    self.next_seq = tcp_packet.seq_num + data_len

                    # Send ACK
                    return TCPPacket(
                        src_port=self.local_port,
                        dest_port=self.remote_port,
                        seq_num=self.seq_num,
                        ack_num=self.next_seq,
                        flags=TCPPacket.ACK,
                        data=b"",
                    )
                else:

                    # Out of sequence, send duplicate ACK
                    return TCPPacket(
                        src_port=self.local_port,
                        dest_port=self.remote_port,
                        seq_num=self.seq_num,
                        ack_num=self.next_seq,
                        flags=TCPPacket.ACK,
                        data=b"",
                    )

        elif self.state == TCPSession.LAST_ACK:
            if tcp_packet.is_ack():
                # Connection closed
                self.state = TCPSession.CLOSED
                return None

        # Default response - no action needed

        return None

    def send_data(self, data):
        """
        Prepare a packet to send data over the established connection
        """
        if self.state != TCPSession.ESTABLISHED:
            raise ValueError(
                f"Cannot send data in current state: {self.get_state_name()}"
            )

        from models.tcp_packet import TCPPacket

        # Convert string data to bytes if needed
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        elif isinstance(data, bytes) or isinstance(data, bytearray):
            data_bytes = data
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")

        # Create data packet
        packet = TCPPacket(
            src_port=self.local_port,
            dest_port=self.remote_port,
            seq_num=self.seq_num,
            ack_num=self.next_seq,
            flags=TCPPacket.PSH | TCPPacket.ACK,
            data=data_bytes,
        )

        # Update sequence number
        self.seq_num += len(data_bytes)

        return packet

    def close(self):
        """
        Initiate connection termination
        """
        if self.state not in [TCPSession.ESTABLISHED, TCPSession.SYN_RECEIVED]:
            print(f"Cannot close connection in current state: {self.state}")
            return None

        # Update state
        self.state = TCPSession.FIN_WAIT

        from models.tcp_packet import TCPPacket

        # Create FIN packet
        return TCPPacket(
            src_port=self.local_port,
            dest_port=self.remote_port,
            seq_num=self.seq_num,
            ack_num=self.next_seq,
            flags=TCPPacket.FIN,
            data="",
        )

    def get_state_name(self):
        """Return the name of the current state"""
        states = {
            0: "CLOSED",
            1: "LISTEN",
            2: "SYN_SENT",
            3: "SYN_RECEIVED",
            4: "ESTABLISHED",
            5: "FIN_WAIT",
            6: "CLOSING",
            7: "LAST_ACK",
            8: "TIME_WAIT",
        }
        return states.get(self.state, "UNKNOWN")

    def __str__(self):
        """String representation for debugging"""
        remote = (
            f"{self.remote_ip}:{self.remote_port}"
            if self.remote_ip
            else "Not connected"
        )
        return (
            f"TCPSession[local={self.local_ip}:{self.local_port}, remote={remote}, "
            f"state={self.get_state_name()}, seq={self.seq_num}, next_seq={self.next_seq}]"
        )
