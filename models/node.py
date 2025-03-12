import socket
import threading
import sys
import traceback
from .ethernet_frame import EthernetFrame
from .ip_packet import IPPacket
from .ping_protocol import PingProtocol
from functools import wraps


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

        # ARP Table: Maps IP addresses to MAC addresses
        self.arp_table = {}

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Allow reusing the address to avoid
            # "Address already in use" in quick restarts
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((Node.HOST_IP, self.port))
            self.sock.listen(1)
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

        # Add a sequence counter for Ping Protocol messages
        self.ping_sequence = 0

        # Track ping requests for matching responses
        self.ping_requests = {}

        # Command registry: Maps command names to handler functions and help text
        self.commands = {}

        # Register built-in commands
        self.register_default_commands()

    def init_arp_table(self, arp_entries):
        """Initialize the ARP table with known IP-to-MAC mappings"""
        self.arp_table = arp_entries

    def get_mac_for_ip(self, ip_address):
        """Look up MAC address for a given IP"""
        if ip_address in self.arp_table:
            return self.arp_table[ip_address]
        return self.default_gateway  # If not in ARP table, use default gateway

    def send_frame(self, destination_mac, data):
        """
        Send an Ethernet frame to all other nodes in the same network (Ethernet broadcast).
        Each node that receives it decides if it is the intended recipient or not.

        Args:
            destination_mac: MAC address of destination (2 characters)
            data: data to send in the frame
        """
        frames = []

        for i in range(0, len(data), Node.MAX_DATA_LENGTH):
            chunk = data[i : i + Node.MAX_DATA_LENGTH]
            frames.append(chunk)

        # Send each frame (if there are multiple frames)
        for frame_data in frames:
            for node_mac in self.network:
                if node_mac != self.mac_address:  # Skip sending to itself
                    destination_port = self.process_node_mac(node_mac)
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.connect((Node.HOST_IP, destination_port))
                            frame = EthernetFrame(
                                self.mac_address, destination_mac, frame_data
                            )
                            s.sendall(frame.encode())
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
        if mac_address[-2] == "R":
            # Router ports are BASE_PORT + 3 + router_number
            port = Node.BASE_PORT + 3 + int(mac_address[-1])
        else:
            # Node ports are BASE_PORT + node_number
            port = Node.BASE_PORT + int(mac_address[-1])
        return port

    def listen_for_frames(self):
        """Listen for incoming Ethernet frames"""
        while self.is_running:
            try:
                conn, addr = self.sock.accept()
                with conn:
                    raw_data = conn.recv(2 + 2 + 1 + Node.MAX_DATA_LENGTH)
                    if not raw_data:
                        continue  # Connection closed or no data
                    frame = raw_data.decode("utf-8")
                    self.process_frame(frame)
            except OSError:
                # This can happen if the socket is closed while waiting for accept()
                if self.is_running:
                    print(f"Node {self.mac_address} socket accept() error.")
                break
            except Exception:
                print("Error in listen_for_frames:")
                traceback.print_exc()

    def process_frame(self, frame):
        """Process a received Ethernet frame"""
        if len(frame) < 5:
            print(f"Node {self.mac_address} received invalid frame: {frame}")
            return

        source_mac = frame[0:2]
        destination_mac = frame[2:4]
        data_length = ord(frame[4:5])
        data = frame[5 : 5 + data_length]

        if destination_mac == self.mac_address:
            print(f"Node {self.mac_address} received Ethernet frame from {source_mac}")

            # Check if it contains an IP packet (at least 4 bytes for IP header)
            if len(data) >= 4:
                try:
                    # Try to parse as IP packet
                    ip_packet = IPPacket.decode(data)
                    self.process_ip_packet(ip_packet)
                except:
                    # If it's not an IP packet, just treat as raw data
                    print(f"  Data: {data}")
        else:
            print(
                f"Node {self.mac_address} dropped frame from {source_mac} intended for {destination_mac}"
            )

    def process_ip_packet(self, ip_packet: IPPacket):
        """Process a received IP packet"""

        if ip_packet.dest_ip == self.ip_address:
            print(
                f"  Received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
            )
            print(f"  Protocol: {ip_packet.protocol}, Data length: {ip_packet.length}")

            # Handle different protocols
            if ip_packet.protocol == PingProtocol.PROTOCOL:
                self.handle_ping_protocol(ip_packet)
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

    # Command registration decorator
    def command(self, name, help_text):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            # Register the command in the command registry
            self.commands[name] = {"handler": wrapper, "help": help_text}
            return wrapper

        return decorator

    def register_default_commands(self):
        """Register the default commands"""

        @self.command("ping", "<ip_hex> - Send a ping to the specified IP")
        def cmd_ping(self, args):
            if not args:
                print("Invalid input. Usage: ping <ip_hex>")
                return

            try:
                # Convert hex string to integer
                dest_ip = int(args[0], 16)
                # Send Ping
                self.send_echo(dest_ip)
            except ValueError:
                print("Invalid IP address. Please enter a valid hex value (e.g., 2A)")

        @self.command("arp", "- Display the ARP table")
        def cmd_arp(self, args):
            print("ARP Table:")
            for ip, mac in self.arp_table.items():
                print(f"  0x{ip:02X} -> {mac}")

        @self.command("help", "- Show this help message")
        def cmd_help(self, args):
            self.display_help()

        @self.command("q", "- Exit")
        def cmd_quit(self, args):
            return False

    def display_help(self):
        """Display help information for the command interface"""
        print(
            f"{self.mac_address} started with IP 0x{self.ip_address:02X} ({self.ip_address})"
        )
        print("Available commands:")

        # Display the raw frame sending help
        print("  <destination> <message> - Send raw Ethernet frame")

        # Display help for registered commands
        for cmd_name, cmd_info in self.commands.items():
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

                # Handle raw frame sending (original functionality)
                elif cmd in self.VALID_DESTINATION:
                    if not args:
                        print("Invalid input. Please provide data.")
                        continue

                    destination = cmd
                    data = " ".join(args)

                    self.send_frame(destination, data)
                    print(f"Ethernet frame sent to {destination} with data: {data}")

                else:
                    print("Invalid command or destination.")
                    print("Use 'help' to see available commands")

        except KeyboardInterrupt:
            print("\nKeyboardInterrupt received. Exiting...")
        finally:
            self.shutdown()
            return

    def shutdown(self):
        """Shutdown the node and close connections"""
        self.is_running = False
        try:
            self.sock.close()
        except Exception as e:
            print(f"Error closing socket on port {self.port}: {e}")

        # Join the listening thread to ensure it finishes
        if self.listen_thread.is_alive():
            self.listen_thread.join()
