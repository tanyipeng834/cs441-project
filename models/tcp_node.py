from models.node import Node
from models.ping_protocol import PingProtocol
from models.tcp_packet import TCPPacket
from models.tcp_session import TCPSession


class TCPNode(Node):
    """
    A node that implements TCP functionality for reliable data transfer
    """

    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)

        # TCP sessions storage
        # Key: (local_port, remote_ip, remote_port) - Identifies a unique connection
        # Value: TCPSession object
        self.tcp_sessions = {}

        # Listening ports
        # Key: local_port, Value: TCPSession in LISTEN state
        self.listening_ports = {}

        # Register TCP-specific commands
        self.register_tcp_commands()

    def register_tcp_commands(self):
        @self.command("tcp_listen", "<port> - Start listening on specified TCP port")
        def cmd_tcp_listen(self: TCPNode, args):
            if not args:
                print("Invalid input. Usage: tcp_listen <port>")
                return

            try:
                local_port = int(args[0])
                if local_port < 1 or local_port > 255:
                    print("Port must be between 1 and 255")
                    return

                # Create a new session in LISTEN state
                session = TCPSession(self.ip_address, local_port)
                session.start_passive_open()

                # Store in listening ports
                self.listening_ports[local_port] = session

                print(f"TCP listening on port {local_port}")
            except ValueError:
                print("Invalid port number")

        @self.command(
            "tcp_connect",
            "<dest_ip> <dest_port> <local_port> - Initiate TCP connection",
        )
        def cmd_tcp_connect(self: TCPNode, args):
            if len(args) != 3:
                print(
                    "Invalid input. Usage: tcp_connect <dest_ip> <dest_port> <local_port>"
                )
                return

            try:
                dest_ip = int(args[0], 16)
                dest_port = int(args[1])
                local_port = int(args[2])

                if (
                    dest_port < 1
                    or dest_port > 255
                    or local_port < 1
                    or local_port > 255
                ):
                    print("Ports must be between 1 and 255")
                    return

                # Create new TCP session
                session = TCPSession(self.ip_address, local_port, dest_ip, dest_port)

                # Initiate connection
                syn_packet = session.start_active_open()

                # Store session
                session_key = (local_port, dest_ip, dest_port)
                self.tcp_sessions[session_key] = session

                # Send SYN packet
                self.send_tcp_packet(dest_ip, syn_packet)

                print(
                    f"Initiating TCP connection to 0x{dest_ip:02X}:{dest_port} from local port {local_port}"
                )
            except ValueError as e:
                print(f"Error: {e}")

        @self.command(
            "tcp_send",
            "<local_port> <message> - Send data over established TCP connection",
        )
        def cmd_tcp_send(self: TCPNode, args):
            if len(args) < 2:
                print("Invalid input. Usage: tcp_send <local_port> <message>")
                return

            try:
                local_port = int(args[0])
                message = " ".join(args[1:])

                # Find the session for this local port
                session = None
                for key, s in self.tcp_sessions.items():
                    if key[0] == local_port and s.state == TCPSession.ESTABLISHED:
                        session = s
                        break

                if not session:
                    print(f"No established TCP connection on port {local_port}")
                    return

                # Create and send data packet
                data_packet = session.send_data(message)
                self.send_tcp_packet(session.remote_ip, data_packet)

                print(
                    f"Sent {len(message)} bytes to 0x{session.remote_ip:02X}:{session.remote_port}"
                )
            except ValueError as e:
                print(f"Error: {e}")

        @self.command("tcp_close", "<local_port> - Close TCP connection")
        def cmd_tcp_close(self: TCPNode, args):
            if not args:
                print("Invalid input. Usage: tcp_close <local_port>")
                return

            try:
                local_port = int(args[0])

                # Find the session for this local port
                session = None
                session_key = None
                for key, s in self.tcp_sessions.items():
                    if key[0] == local_port:
                        session = s
                        session_key = key
                        break

                if not session:
                    print(f"No TCP connection on port {local_port}")
                    return

                # Initiate connection close
                fin_packet = session.close()
                if fin_packet:
                    self.send_tcp_packet(session.remote_ip, fin_packet)
                    print(
                        f"Closing TCP connection to 0x{session.remote_ip:02X}:{session.remote_port}"
                    )

                # If connection is fully closed, remove it
                if session.state == TCPSession.CLOSED:
                    del self.tcp_sessions[session_key]
            except ValueError as e:
                print(f"Error: {e}")

        @self.command("tcp_status", "- Show all TCP connections")
        def cmd_tcp_status(self: TCPNode, args):
            if not self.tcp_sessions and not self.listening_ports:
                print("No TCP connections")
                return

            print("TCP Connections:")

            # Show listening ports
            for port, session in self.listening_ports.items():
                print(f"  Port {port}: LISTENING")

            # Show established and other connections
            for key, session in self.tcp_sessions.items():
                local_port, remote_ip, remote_port = key
                print(
                    f"  Local port {local_port} <-> 0x{remote_ip:02X}:{remote_port} - {session.get_state_name()}"
                )
                print(f"    SEQ: {session.seq_num}, NEXT: {session.next_seq}")
                if session.received_data:
                    print(f"    Received: {len(session.received_data)} messages")

    def send_tcp_packet(self, dest_ip, tcp_packet):
        """Send a TCP packet encapsulated in an IP packet"""
        # Encode the TCP packet
        tcp_data = tcp_packet.encode()

        # Send it in an IP packet
        self.send_ip_packet(dest_ip, TCPPacket.PROTOCOL, tcp_data)

    def process_ip_packet(self, ip_packet):
        """Process a received IP packet, handling TCP if appropriate"""

        if ip_packet.dest_ip == self.ip_address or ip_packet.dest_ip == 0xFF:
            print(
                f"  Received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
            )
            print(f"  Protocol: {ip_packet.protocol}, Data length: {ip_packet.length}")

            # Handle TCP protocol
            if ip_packet.protocol == TCPPacket.PROTOCOL:
                try:
                    tcp_packet = TCPPacket.decode(ip_packet.data)
                    print(f"  Received TCP packet: {tcp_packet}")
                    self.process_tcp_packet(tcp_packet, ip_packet.source_ip)
                except ValueError as e:
                    print(f"  Error decoding TCP packet: {e}")
            elif ip_packet.protocol == PingProtocol.PROTOCOL:
                # Handle Ping Protocol as before
                self.handle_ping_protocol(ip_packet)
            else:
                print(
                    f"  Unknown protocol: {ip_packet.protocol}, Data: {ip_packet.data}"
                )
        else:
            print(f"  Dropped IP packet intended for 0x{ip_packet.dest_ip:02X}")

    def process_tcp_packet(self, tcp_packet, source_ip):
        """Process a TCP packet and update the appropriate session"""

        # Check if this matches an existing session
        session_key = (tcp_packet.dest_port, source_ip, tcp_packet.src_port)

        if session_key in self.tcp_sessions:
            # Existing session
            session = self.tcp_sessions[session_key]

            # Process the packet
            response = session.handle_packet(tcp_packet, source_ip)

            # Check if session should be removed (closed)
            if session.state == TCPSession.CLOSED:
                del self.tcp_sessions[session_key]
                print(f"TCP connection closed and removed")

            # Send response if needed
            if response:
                self.send_tcp_packet(source_ip, response)

            # Process any received data
            if session.received_data:
                for data in session.received_data:
                    print(f"TCP data received on port {tcp_packet.dest_port}: {data}")
                session.received_data = []  # Clear after processing

        # Check if this is for a listening port (new connection)
        elif tcp_packet.dest_port in self.listening_ports and tcp_packet.is_syn():
            # Get the listening session
            listen_session = self.listening_ports[tcp_packet.dest_port]

            # Handle the SYN packet
            response = listen_session.handle_packet(tcp_packet, source_ip)

            # If state changed to SYN_RECEIVED, create a new session
            if listen_session.state == TCPSession.SYN_RECEIVED:
                # Create new session based on the listening session
                new_session = TCPSession(
                    self.ip_address,
                    tcp_packet.dest_port,
                    source_ip,
                    tcp_packet.src_port,
                )
                new_session.state = TCPSession.SYN_RECEIVED
                new_session.seq_num = listen_session.seq_num
                new_session.next_seq = listen_session.next_seq

                # Store the new session
                self.tcp_sessions[session_key] = new_session

                # Reset listen session back to LISTEN state
                listen_session.state = TCPSession.LISTEN
                listen_session.remote_ip = None
                listen_session.remote_port = None

            # Send response if needed
            if response:
                self.send_tcp_packet(source_ip, response)

        else:
            # No matching session or listening port
            print(
                f"Received TCP packet for unknown session or closed port: {tcp_packet.dest_port}"
            )

            # Send RST packet if not a RST packet itself
            if not tcp_packet.is_rst():
                rst_packet = TCPPacket(
                    src_port=tcp_packet.dest_port,
                    dest_port=tcp_packet.src_port,
                    seq_num=0,
                    ack_num=(
                        tcp_packet.seq_num + 1
                        if tcp_packet.is_syn()
                        else tcp_packet.seq_num
                    ),
                    flags=TCPPacket.RST,
                    data="",
                )
                self.send_tcp_packet(source_ip, rst_packet)
