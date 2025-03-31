import socket
import threading
import sys
import time
import traceback
import queue
from .arp_packet import ARPPacket
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
        self.queue = queue.Queue(maxsize=3)
        self.packets_dropped = 0
        self.sleep_event = threading.Event()

        # ARP Table: Maps IP addresses to MAC addresses
        self.arp_table = {}
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

    def init_arp_table(self, arp_entries):
        """Initialize the ARP table with known IP-to-MAC mappings"""
        self.arp_table = arp_entries

    def get_mac_for_ip(self, ip_address):
        if ip_address == 0xFF:
            return "FF"

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
                # This can happen if the socket is closed while waiting for accept()
                if self.is_running:
                    print(f"Node {self.mac_address} socket accept() error.")
                break
            except Exception:
                print("Error in listen_for_frames:")
                traceback.print_exc()

    def decode_frame(self, frame):
        """Decode an Ethernet frame"""
        try:
            if len(frame) < 5:
                raise ValueError("Frame must be at least 5 bytes long")

            source_mac = frame[0:2]
            destination_mac = frame[2:4]
            data_length = ord(frame[4:5])
            data = frame[5 : 5 + data_length]

            return source_mac, destination_mac, data_length, data
        except Exception:
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
                if data.startswith("ARP"):
                    try:
                        arp_packet = ARPPacket.decode(data)
                        print(f"  Received ARP packet: {arp_packet}")
                        self.process_arp_packet(arp_packet)
                    except ValueError as e:
                        print(f"  Error decoding ARP packet: {e}")
                else:
                    # Try to parse as IP packet
                    try:
                        ip_packet = IPPacket.decode(data)
                        # Add IP packet to processing queue
                        self.add_ip_packet_to_queue(ip_packet)

                    except Exception:
                        print(f"  Data: {data}")

            else:
                print(
                    f"Node {self.mac_address} dropped frame from {source_mac} intended for {destination_mac}"
                )

        except Exception as e:
            print(f"Error processing frame: {frame} - {e}")

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
            except Exception:
                pass

    def process_ip_packet(self, ip_packet: IPPacket):
        """Process a received IP packet"""
        if ip_packet.dest_ip == self.ip_address or ip_packet.dest_ip == 0xFF:
            print(
                f"  Received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
            )
            
            print(f"  Protocol: {ip_packet.protocol}, Data length: {ip_packet.length}")
            if ip_packet.node is not None:
                ip_packet.node = int(ip_packet.node)
                print(f"  Node Sampled: 0x{ip_packet.node:02X}")

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
