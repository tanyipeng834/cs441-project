import socket
import threading
import sys
import time
import traceback
import queue
from functools import wraps

# Import all the needed modules - make sure these imports work in your environment
from .arp_packet import ARPPacket
from .ethernet_frame import EthernetFrame
from .ip_packet import IPPacket
from .ping_protocol import PingProtocol
from .tcp_packet import TCPPacket
from .tcp_session import TCPSession


class Node:
    MAX_DATA_LENGTH = 256
    HOST_IP = "127.0.0.1"
    BASE_PORT = 50000
    VALID_DESTINATION = ["N1", "N2", "N3", "R1", "R2"]

    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        self.mac_address = mac_address
        self.ip_address = ip_address  # IP address in hex (e.g., 0x1A)
        self.port = port
        self.network = network
        self.default_gateway = default_gateway  # MAC address of default gateway
        self.queue = queue.Queue(maxsize=3)
        self.packets_dropped = 0
        self.sleep_event = threading.Event()

        # ARP Table: Maps IP addresses to MAC addresses
        self.arp_table = {}
        # Merge port mappings from both implementations
        self.port_mapping = {
            "N1": 50001,
            "N2": 50002,
            "N3": 50003,
            "N4": 50004,
            "N5": 50005,
            "N6": 50006,
            "N7": 50007,
            "N8": 50008,
            "N9": 50009,
            "NA": 50010,
            "NB": 50011,
            "R1": 50012,
            "R2": 50013,
            "R3": 50014,
            "R4": 50015,
            "R5": 50016,
            "R6": 50017,
            "R7": 50018,
            "R8": 50019,
        }

        # TCP-specific attributes
        # TCP sessions storage
        # Key: (local_port, remote_ip, remote_port) - Identifies a unique connection
        # Value: TCPSession object
        self.tcp_sessions = {}

        # Listening ports
        # Key: local_port, Value: TCPSession in LISTEN state
        self.listening_ports = {}

        # Using UDP socket instead of TCP for better compatibility with UDP features
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Allow reusing the address to avoid
            # "Address already in use" in quick restarts
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((Node.HOST_IP, self.port))
        except socket.error as e:
            print(f"Error starting node on port {self.port}: {e}")
            sys.exit(1)

        print(
            f"Node {self.mac_address} (IP: 0x{self.ip_address:02X}) started on port {self.port}."
        )

        # Flag to control the listening loop
        self.is_running = True

        # Start a non-daemon thread to listen for incoming frames
        self.listen_thread = threading.Thread(target=self.listen_for_frames)
        self.listen_thread.start()

        # Start thread to process IP packets from the queue
        self.process_thread = threading.Thread(target=self.process_queue)
        self.process_thread.start()

        # Add a sequence counter for Ping Protocol messages
        self.ping_sequence = 0

        # Track ping requests for matching responses
        self.ping_requests = {}

        # Command registry: Maps command names to handler functions and help text
        self.commands = {}

        # Register built-in commands
        self.register_default_commands()

        # Register TCP commands
        self.register_tcp_commands()

    def init_arp_table(self, arp_entries):
        """Initialize the ARP table with known IP-to-MAC mappings"""
        self.arp_table = arp_entries

    def get_mac_for_ip(self, ip_address):
        """Look up MAC address for a given IP"""
        if ip_address == 0xFF:
            return "FF"

        if ip_address in self.arp_table:
            return self.arp_table[ip_address]
        return self.default_gateway  # If not in ARP table, use default gateway

    def send_frame(self, destination_mac, data):
        """
        Send an Ethernet frame to all other nodes in the same network.

        Args:
            destination_mac: MAC address of destination (2 characters)
            data: data to send in the frame (bytes or string)
        """
        # Ensure data is bytes
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        # Calculate maximum data length and split into chunks if needed
        frames = []

        for i in range(0, len(data_bytes), Node.MAX_DATA_LENGTH):
            chunk = data_bytes[i : i + Node.MAX_DATA_LENGTH]
            frames.append(chunk)
        
        print(frames)

        # Send each frame to all nodes in the network
        for frame_data in frames:
            for node_mac in self.network:
                if node_mac != self.mac_address:  # Skip sending to itself
                    destination_port = self.process_node_mac(node_mac)
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                            frame = EthernetFrame(
                                self.mac_address, destination_mac, frame_data
                            )
                            s.sendto(frame.encode(), (Node.HOST_IP, destination_port))
                    except Exception as e:
                        print(
                            f"Error sending frame from {self.mac_address} to port {destination_port}: {e}"
                        )

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
            ip_packet = IPPacket(self.ip_address, destination_ip, protocol, chunk)
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
        ping_protocol = PingProtocol.create_echo_request(
            identifier=self.ip_address,  # Use our IP as the identifier
            sequence=self.ping_sequence,
            data=data,
        )

        # Send the Ping Protocol packet encapsulated in an IP packet
        self.send_ip_packet(
            destination_ip=destination_ip,
            protocol=PingProtocol.PROTOCOL,
            data=ping_protocol.encode(),
        )

        # Store ping request for tracking responses
        self.ping_requests[self.ping_sequence] = {
            "responded": False,
            "destination": destination_ip,
        }
        print(
            f"Sent Ping Protocol Echo Request to 0x{destination_ip:02X} (seq={self.ping_sequence})"
        )

        return self.ping_sequence  # Return sequence for tracking

    def process_node_mac(self, mac_address):
        """Convert MAC address to port number"""
        return self.port_mapping[mac_address]

    def listen_for_frames(self):
        """Listen for incoming Ethernet frames"""
        while self.is_running:
            try:
                raw_data, addr = self.sock.recvfrom(2 + 2 + 1 + Node.MAX_DATA_LENGTH)
                if not raw_data:
                    continue  # no data received
                try:
                    frame = raw_data.decode("utf-8")
                except UnicodeDecodeError:
                    frame = raw_data

                self.process_frame(frame)
            except OSError:
                # This can happen if the socket is closed while waiting
                if self.is_running:
                    print(f"Node {self.mac_address} socket error.")
                break
            except Exception:
                print("Error in listen_for_frames:")
                traceback.print_exc()

    def decode_frame(self, frame):
        """Decode an Ethernet frame"""
        try:
            # Make sure we're working with bytes
            if isinstance(frame, str):
                frame_bytes = bytearray()
                for c in frame:
                    frame_bytes.append(ord(c))
                frame_bytes = bytes(frame_bytes)
            else:
                frame_bytes = frame

            if len(frame_bytes) < 5:
                raise ValueError(
                    f"Frame too short to be an Ethernet frame: length={len(frame_bytes)}"
                )

            # Decode header fields
            source = frame_bytes[0:2].decode("utf-8")
            destination = frame_bytes[2:4].decode("utf-8")
            data_length = frame_bytes[4]

            # Extract data
            data = (
                frame_bytes[5 : 5 + data_length]
                if len(frame_bytes) >= 5 + data_length
                else frame_bytes[5:]
            )

            return source, destination, data_length, data

        except Exception as e:
            print(f"[ERROR] DECODE_FRAME_ERROR: {e}")
            traceback.print_exc()
            raise

    def process_frame(self, frame):
        """Process a received Ethernet frame"""
        try:
            source_mac, destination_mac, _, data = self.decode_frame(frame)

            if destination_mac == self.mac_address or destination_mac == "FF":
                print(
                    f"Node {self.mac_address} received Ethernet frame from {source_mac}"
                )

                # Check if it's an ARP packet (starts with 'ARP')
                if data.startswith(b"ARP"):
                    try:
                        arp_packet = ARPPacket.decode(data)
                        print(f"  Received ARP packet: {arp_packet}")
                        self.process_arp_packet(arp_packet)
                    except ValueError as e:
                        print(f"  Error decoding ARP packet: {e}")
                else:
                    try:
                        ip_packet = IPPacket.decode(data)
                        self.add_ip_packet_to_queue(ip_packet)
                    except Exception:
                        print(
                            f"  Raw Ethernet data: {data.decode()}"
                        )
            else:
                print(
                    f"Node {self.mac_address} dropped frame from {source_mac} intended for {destination_mac}"
                )

        except Exception as e:
            print(f"Error processing frame: {e}")
            traceback.print_exc()

    def add_ip_packet_to_queue(self, ip_packet: IPPacket):
        """Add an IP packet to the processing queue"""
        try:
            self.queue.put_nowait(ip_packet)
            current_size = self.queue.qsize()
            print(f"  Queue size: {current_size}/{self.queue.maxsize}")
        except queue.Full:
            print(f"  Queue full, dropping IP packet from 0x{ip_packet.source_ip:02X}")
            self.packets_dropped += 1

    def process_queue(self):
        """Process IP packets in the queue"""
        while self.is_running:
            # Add delay to simulate processing time
            self.sleep_event.wait(timeout=1)
            try:
                ip_packet = self.queue.get_nowait()
                if ip_packet:
                    self.process_ip_packet(ip_packet)
            except queue.Empty:
                pass
            except Exception as e:
                print(f"Error processing queue: {e}")
                traceback.print_exc()

    def process_ip_packet(self, ip_packet: IPPacket):
        """Process a received IP packet"""
        if ip_packet.dest_ip == self.ip_address or ip_packet.dest_ip == 0xFF:
            print(
                f"  Received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
            )
            print(f"  Protocol: {ip_packet.protocol}, Data length: {ip_packet.length}")

            # Check for node field from the original implementation
            print(ip_packet)
            if ip_packet.node is not None:

                if isinstance(ip_packet.node, bytes):
                    try:
                        ip_packet.node = int(ip_packet.node.decode("utf-8"))
                    except ValueError:
                        ip_packet.node = int.from_bytes(ip_packet.node, byteorder="big")

                print(f"  Node Sampled: {hex(ip_packet.node)}")

            # Handle different protocols
            if ip_packet.protocol == PingProtocol.PROTOCOL:
                self.handle_ping_protocol(ip_packet)
            elif ip_packet.protocol == TCPPacket.PROTOCOL:
                try:
                    tcp_packet = TCPPacket.decode(ip_packet.data)
                    print(f"  Received TCP packet: {tcp_packet}")
                    self.process_tcp_packet(tcp_packet, ip_packet.source_ip)
                except Exception as e:
                    print(f"  Error processing TCP packet: {e}")
                    print(f"  TCP data: {ip_packet.data}")
            else:
                print(
                    f"  Unknown protocol: {ip_packet.protocol}, Data: {ip_packet.data}"
                )
        else:
            print(f"  Dropped IP packet intended for 0x{ip_packet.dest_ip:02X}")

    def handle_ping_protocol(self, ip_packet: IPPacket):
        """Handle Ping Protocol packets"""
        try:
            ping_protocol = PingProtocol.decode(ip_packet.data)
            print(f"  Received Ping Protocol packet: {ping_protocol}")

            if ping_protocol.is_echo_request():
                print(
                    f"  Echo request received from 0x{ip_packet.source_ip:02X}, sending reply"
                )

                # Create and send echo reply with same ID, sequence, and data
                reply = PingProtocol.create_echo_reply(
                    ping_protocol.identifier, ping_protocol.sequence, ping_protocol.data
                )

                self.send_ip_packet(
                    destination_ip=ip_packet.source_ip,
                    protocol=PingProtocol.PROTOCOL,
                    data=reply.encode(),
                )

            elif ping_protocol.is_echo_reply():
                # If we get an echo reply, check if it matches one of our requests
                print(f"  Echo reply received from 0x{ip_packet.source_ip:02X}")

                if ping_protocol.sequence in self.ping_requests:
                    request = self.ping_requests[ping_protocol.sequence]
                    if (
                        not request["responded"]
                        and request["destination"] == ip_packet.source_ip
                    ):
                        request["responded"] = True
                        print(
                            f"  Matched ping request sequence {ping_protocol.sequence}"
                        )
                        print(f"  Reply data: {ping_protocol.data}")
                    else:
                        print(
                            f"  Duplicate or mismatched reply for sequence {ping_protocol.sequence}"
                        )
                else:
                    print(
                        f"  Unexpected echo reply with sequence {ping_protocol.sequence}"
                    )

            else:
                # Handle other Ping Protocol message types
                if ping_protocol.ping_type == PingProtocol.DEST_UNREACHABLE:
                    print(f"  Destination unreachable: code {ping_protocol.code}")
                elif ping_protocol.ping_type == PingProtocol.TIME_EXCEEDED:
                    print(f"  Time exceeded: code {ping_protocol.code}")
                else:
                    print(
                        f"  Other Ping Protocol message: type {ping_protocol.ping_type}, code {ping_protocol.code}"
                    )

        except Exception as e:
            print(f"  Error processing Ping Protocol packet: {e}")
            traceback.print_exc()

    def process_arp_packet(self, arp_packet: ARPPacket):
        """Process an ARP Packet received in an Ethernet frame"""
        # Update our ARP table with the received mapping
        old_mac = self.arp_table.get(arp_packet.source_ip)
        self.arp_table[arp_packet.source_ip] = arp_packet.source_mac

        if old_mac and old_mac != arp_packet.source_mac:
            print(
                f"  !! ARP entry changed for IP 0x{arp_packet.source_ip:02X}: {old_mac} -> {arp_packet.source_mac}"
            )
        else:
            print(
                f"  Updated ARP table: IP 0x{arp_packet.source_ip:02X} -> {arp_packet.source_mac}"
            )

    def process_arp_message(self, source_mac, data):
        """Process an ARP message received in an Ethernet frame"""
        try:
            # Parse the ARP message
            # Format: ARP_RESPONSE:IP:MAC
            parts = data.split(":")
            if len(parts) != 3 or parts[0] != "ARP":
                print(f"Invalid ARP message format: {data}")
                return

            advertised_ip = int(parts[1], 16)
            advertised_mac = parts[2]

            # Update our ARP table with the received mapping
            old_mac = self.arp_table.get(advertised_ip)
            self.arp_table[advertised_ip] = advertised_mac

            if old_mac and old_mac != advertised_mac:
                print(
                    f"!! ARP entry changed for IP 0x{advertised_ip:02X}: {old_mac} -> {advertised_mac}"
                )
            else:
                print(
                    f"Updated ARP table: IP 0x{advertised_ip:02X} -> {advertised_mac}"
                )

        except Exception as e:
            print(f"Error processing ARP message: {e}")

    # TCP-specific methods
    def send_tcp_packet(self, dest_ip, tcp_packet):
        """Send a TCP packet encapsulated in an IP packet"""
        # Encode the TCP packet
        tcp_data = tcp_packet.encode()

        # Send it in an IP packet
        self.send_ip_packet(dest_ip, TCPPacket.PROTOCOL, tcp_data)

    def process_tcp_packet(self, tcp_packet, source_ip):
        """Process a TCP packet and update the appropriate session"""

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

        # Check if this matches an existing session
        session_key = (tcp_packet.dest_port, source_ip, tcp_packet.src_port)

        # Normal session lookup
        if session_key in self.tcp_sessions:
            # Existing session
            session = self.tcp_sessions[session_key]

            # Display received data if this is a data packet (PSH flag)
            if tcp_packet.is_psh() and len(tcp_packet.data) > 0:
                data_content = ""
                if isinstance(tcp_packet.data, bytes):
                    try:
                        data_content = tcp_packet.data.decode("utf-8")
                    except UnicodeDecodeError:
                        data_content = f"<binary data of {len(tcp_packet.data)} bytes>"
                else:
                    data_content = tcp_packet.data

                print(
                    f'\nMessage received from 0x{source_ip:02X}:{tcp_packet.src_port}: "{data_content}"\n'
                )

            # Process the packet
            response = session.handle_packet(tcp_packet, source_ip)

            # NEW CODE: Check for the special flag "CLOSE_ONLY_THIS_END"
            if response == "CLOSE_ONLY_THIS_END":
                print(f"Closing only this end of the TCP connection due to RST")
                del self.tcp_sessions[session_key]
                return

            # Check if session should be removed (closed)
            if session.state == TCPSession.CLOSED:
                del self.tcp_sessions[session_key]

            # Send response if needed
            if response:
                self.send_tcp_packet(source_ip, response)

            # Process any received data
            if session.received_data:
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
                if hasattr(listen_session, "connection_established_notified"):
                    new_session.connection_established_notified = False

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
            # If this is an ACK packet, it might be for a SYN-RECEIVED session
            if (
                tcp_packet.is_ack()
                and not tcp_packet.is_syn()
                and not tcp_packet.is_fin()
            ):
                # Check all sessions for a matching SYN-RECEIVED state
                for key, session in self.tcp_sessions.items():
                    if (
                        session.state == TCPSession.SYN_RECEIVED
                        and session.local_port == tcp_packet.dest_port
                        and session.remote_port == tcp_packet.src_port
                        and session.remote_ip == source_ip
                    ):

                        response = session.handle_packet(tcp_packet, source_ip)

                        # Send response if needed (unlikely for an ACK)
                        if response:
                            self.send_tcp_packet(source_ip, response)

                        return

            # Only send RST if this isn't already a RST
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
                    data=b"",
                )
                self.send_tcp_packet(source_ip, rst_packet)

    def register_tcp_commands(self):
        """Register TCP-specific commands"""

        @self.command("tcp_listen", "<port> - Start listening on specified TCP port")
        def cmd_tcp_listen(self, args):
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
        def cmd_tcp_connect(self, args):
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

                # Print connection message first for consistent output
                print(
                    f"Initiating TCP connection to 0x{dest_ip:02X}:{dest_port} from local port {local_port}"
                )

                # Create new TCP session
                session = TCPSession(self.ip_address, local_port, dest_ip, dest_port)

                # Initiate connection
                syn_packet = session.start_active_open()

                # Store session - using consistent key structure
                session_key = (local_port, dest_ip, dest_port)
                self.tcp_sessions[session_key] = session

                # Send SYN packet
                self.send_tcp_packet(dest_ip, syn_packet)
            except ValueError as e:
                print(f"Error: {e}")

        @self.command(
            "tcp_send",
            "<local_port> <message> - Send data over established TCP connection",
        )
        def cmd_tcp_send(self, args):
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
                    f'\nMessage sent to 0x{session.remote_ip:02X}:{session.remote_port}: "{message}"\n'
                )

            except ValueError as e:
                print(f"Error: {e}")

        @self.command("tcp_close", "<local_port> - Close TCP connection")
        def cmd_tcp_close(self, args):
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
        def cmd_tcp_status(self, args):
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

        @self.command("tcp_debug_full", "- Complete TCP debugging information")
        def cmd_tcp_debug_full(self, args):
            print("\n==== DETAILED TCP CONNECTION DEBUG ====")

            # Debug TCP Sessions Dictionary
            print("\nTCP Sessions Dictionary:")
            if not self.tcp_sessions:
                print("  Empty - No active sessions")
            else:
                for i, (key, session) in enumerate(self.tcp_sessions.items()):
                    local_port, remote_ip, remote_port = key
                    print(f"  Session #{i+1}:")
                    print(f"    Key: ({local_port}, 0x{remote_ip:02X}, {remote_port})")
                    print(
                        f"    State: {session.get_state_name()} (value: {session.state})"
                    )
                    print(f"    Local: 0x{self.ip_address:02X}:{session.local_port}")
                    print(
                        f"    Remote: 0x{session.remote_ip:02X}:{session.remote_port}"
                    )
                    print(f"    SEQ: {session.seq_num}, NEXT_SEQ: {session.next_seq}")

            # Debug Listening Ports
            print("\nListening Ports:")
            if not self.listening_ports:
                print("  No listening ports")
            else:
                for port, session in self.listening_ports.items():
                    print(f"  Port {port}: LISTENING")

            # Add additional debugging for the current state
            print("\nNode Information:")
            print(f"  MAC Address: {self.mac_address}")
            print(f"  IP Address: 0x{self.ip_address:02X}")
            print(f"  Port: {self.port}")

            # Test key lookup for a specific port
            if args and len(args) > 0:
                test_port = int(args[0])
                print(f"\nTest lookup for local port {test_port}:")
                found = False
                for key, session in self.tcp_sessions.items():
                    local_port, remote_ip, remote_port = key
                    if local_port == test_port:
                        found = True
                        print(
                            f"  Found session with key: ({local_port}, 0x{remote_ip:02X}, {remote_port})"
                        )
                        print(f"  State: {session.get_state_name()}")
                if not found:
                    print(f"  No session found with local port {test_port}")

            print("\n==== END OF TCP DEBUG ====\n")

        # Add these methods after the TCP-specific methods like process_tcp_packet and register_tcp_commands

    # Command registration decorator
    def command(self, name, help_text, default=False):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            # Register the command in the command registry
            self.commands[name] = {
                "handler": wrapper,
                "help": help_text,
                "default": default,
            }
            return wrapper

        return decorator

    def register_default_commands(self):
        """Register the default commands"""

        @self.command("ef", " <destination> <message> - Send raw Ethernet frame", True)
        def cmd_send_frame(self: Node, args):
            if len(args) < 2:
                print("Invalid input. Usage: <destination> <message>")
                return

            destination = args[0]

            if destination not in self.VALID_DESTINATION:
                print(f"Invalid destination: {destination}")
                return

            data = " ".join(args[1:])
            self.send_frame(destination, data)
            print(f"Ethernet frame sent to {destination} with data: {data}")

        @self.command("ip", "<destination> <protocol> <message> - Send IP packet", True)
        def cmd_send_ip_packet(self: Node, args):
            if len(args) < 2:
                print("Invalid input. Usage: <destination> <protocol> <message>")
                return

            destination = int(args[0], 16)
            protocol = int(args[1])
            data = " ".join(args[2:])
            self.send_ip_packet(destination, protocol, data)

        @self.command(
            "ping", "<ip_hex> [-c count] - Send ping(s) to the specified IP", True
        )
        def cmd_ping(self: Node, args):
            if not args:
                print("Invalid input. Usage: ping <ip_hex> [-c count]")
                return

            try:
                # Parse arguments
                dest_ip = int(args[0], 16)
                count = 1  # Default to one ping

                # Check if -c flag is present
                if len(args) >= 3 and args[1] == "-c":
                    try:
                        count = int(args[2])
                        if count < 1:
                            print("Count must be a positive number")
                            return
                    except ValueError:
                        print("Invalid count value. Must be a positive integer.")
                        return

                # Send the ping(s)
                for i in range(count):
                    if count > 1:
                        print(f"Sending ping {i+1}/{count}...")
                        time.sleep(0.1)
                    self.send_echo(dest_ip)

            except ValueError:
                print("Invalid IP address. Please enter a valid hex value (e.g., 2A)")

        @self.command("arp", "- Display the ARP table", True)
        def cmd_arp(self: Node, args):
            print("ARP Table:")
            for ip, mac in self.arp_table.items():
                print(f"  0x{ip:02X} -> {mac}")

        @self.command("stats", "- Display node statistics", True)
        def cmd_stats(self: Node, args):
            print(f"Node {self.mac_address} statistics:")
            print(f"  Packets dropped: {self.packets_dropped}")

        @self.command("help", "- Show this help message", True)
        def cmd_help(self: Node, args):
            self.display_help()

        @self.command("q", "- Exit", True)
        def cmd_quit(self, args):
            return False

    def display_help(self):
        """Display help information for the command interface"""
        print(
            f"{self.mac_address} started with IP 0x{self.ip_address:02X} ({self.ip_address})"
        )
        print("Available commands:")

        # Display help for registered commands
        # Show non-default commands first
        for cmd_name, cmd_info in self.commands.items():
            if not cmd_info["default"]:
                print(f"  {cmd_name} {cmd_info['help']}")

        for cmd_name, cmd_info in self.commands.items():
            if cmd_info["default"]:
                print(f"  {cmd_name} {cmd_info['help']}")

    def run(self):
        """Start an interactive command interface for the node"""
        self.display_help()

        try:
            running = True
            while running:
                user_input = input(f"{self.mac_address}>> ").strip()
                if not user_input:
                    continue

                # Parse the command and arguments
                parts = user_input.split()
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []

                # Check if it's a registered command
                if cmd in self.commands:
                    result = self.commands[cmd]["handler"](self, args)
                    if result is False:  # Command signals to exit
                        print("Exiting...")
                        break
                else:
                    print("Invalid command")
                    print("Use 'help' to see available commands")

        except KeyboardInterrupt:
            print("\nKeyboardInterrupt received. Exiting...")
        finally:
            self.shutdown()
            return

    def shutdown(self):
        """Shutdown the node and close connections"""
        self.is_running = False

        # Stop sleep event
        self.sleep_event.set()

        try:
            self.sock.close()
        except Exception as e:
            print(f"Error closing socket on port {self.port}: {e}")

        # Join the listening thread to ensure it finishes
        if self.listen_thread.is_alive():
            self.listen_thread.join()

        if self.process_thread.is_alive():
            self.process_thread.join()
