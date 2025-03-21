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

        # Window size removed

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

        print(f"Initiating TCP connection to {self.remote_ip}:{self.remote_port}")

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

        # Check if this is from our expected remote endpoint
        if self.state != TCPSession.LISTEN and self.remote_ip != source_ip:
            print(f"Unexpected packet from {source_ip}, expected {self.remote_ip}")
            # Send RST packet for unexpected connection
            return TCPPacket(
                src_port=self.local_port,
                dest_port=tcp_packet.src_port,
                seq_num=self.seq_num,
                ack_num=0,
                flags=TCPPacket.RST,
                data="",
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

                print(
                    f"Received SYN from {source_ip}:{tcp_packet.src_port}, sending SYN-ACK"
                )

                # Send SYN-ACK
                return TCPPacket(
                    src_port=self.local_port,
                    dest_port=self.remote_port,
                    seq_num=self.seq_num,
                    ack_num=self.next_seq,
                    flags=TCPPacket.SYN | TCPPacket.ACK,
                    data="",
                )

        elif self.state == TCPSession.SYN_SENT:
            if tcp_packet.is_syn() and tcp_packet.is_ack():
                # Received SYN-ACK, move to ESTABLISHED
                if tcp_packet.ack_num == self.seq_num + 1:
                    self.seq_num = tcp_packet.ack_num
                    self.next_seq = tcp_packet.seq_num + 1
                    self.state = TCPSession.ESTABLISHED

                    print(
                        f"Received SYN-ACK, connection established with {self.remote_ip}:{self.remote_port}"
                    )

                    # Send ACK
                    return TCPPacket(
                        src_port=self.local_port,
                        dest_port=self.remote_port,
                        seq_num=self.seq_num,
                        ack_num=self.next_seq,
                        flags=TCPPacket.ACK,
                        data="",
                    )

        elif self.state == TCPSession.SYN_RECEIVED:
            if tcp_packet.is_ack():
                # Final ACK received, connection established
                self.state = TCPSession.ESTABLISHED
                self.seq_num = tcp_packet.ack_num

                print(
                    f"Connection established with {self.remote_ip}:{self.remote_port}"
                )
                return None

        elif self.state == TCPSession.ESTABLISHED:
            # Handle data transfer
            if tcp_packet.is_fin():
                # Remote wants to close connection
                self.state = TCPSession.LAST_ACK
                self.next_seq = tcp_packet.seq_num + 1

                print(f"Received FIN from {self.remote_ip}:{self.remote_port}")

                # Send FIN-ACK
                return TCPPacket(
                    src_port=self.local_port,
                    dest_port=self.remote_port,
                    seq_num=self.seq_num,
                    ack_num=self.next_seq,
                    flags=TCPPacket.FIN | TCPPacket.ACK,
                    data="",
                )

            elif len(tcp_packet.data) > 0:
                # Data packet
                if tcp_packet.seq_num == self.next_seq:
                    # In-sequence data
                    self.received_data.append(tcp_packet.data)
                    self.next_seq = tcp_packet.seq_num + len(tcp_packet.data)

                    print(
                        f"Received {len(tcp_packet.data)} bytes from {self.remote_ip}:{self.remote_port}"
                    )

                    # Send ACK
                    return TCPPacket(
                        src_port=self.local_port,
                        dest_port=self.remote_port,
                        seq_num=self.seq_num,
                        ack_num=self.next_seq,
                        flags=TCPPacket.ACK,
                        data="",
                    )
                else:
                    # Out of sequence, send duplicate ACK
                    print(
                        f"Out of sequence data from {self.remote_ip}:{self.remote_port}"
                    )

                    return TCPPacket(
                        src_port=self.local_port,
                        dest_port=self.remote_port,
                        seq_num=self.seq_num,
                        ack_num=self.next_seq,
                        flags=TCPPacket.ACK,
                        data="",
                    )

        elif self.state == TCPSession.LAST_ACK:
            if tcp_packet.is_ack():
                # Connection closed
                self.state = TCPSession.CLOSED
                print(f"Connection with {self.remote_ip}:{self.remote_port} closed")
                return None

        # Default response - no action needed
        return None

    def send_data(self, data):
        """
        Prepare a packet to send data over the established connection
        """
        if self.state != TCPSession.ESTABLISHED:
            raise ValueError(f"Cannot send data in current state: {self.state}")

        from models.tcp_packet import TCPPacket

        # Create data packet
        packet = TCPPacket(
            src_port=self.local_port,
            dest_port=self.remote_port,
            seq_num=self.seq_num,
            ack_num=self.next_seq,
            flags=TCPPacket.PSH | TCPPacket.ACK,
            data=data,
        )

        # Update sequence number
        self.seq_num += len(data)

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
