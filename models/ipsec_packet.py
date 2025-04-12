from .ip_packet import IPPacket


class IPSecPacket:
    def __init__(self, source_ip, dest_ip, mode, ip_packet, mac):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.mode = mode  # 0 for AH, 1 for ESP
        self.ip_packet = ip_packet
        self.mac = mac  # MAC passed during initialization (if applicable)

    def encode(self):
        # Add an identifier at the front to mark the IPSec packet (e.g., 0xA0)
        identifier = bytes([0xA0])  # 0xA0 as the identifier for IPSec packets

        # Start encoding the packet with the identifier
        encoded_data = identifier  # Prepend the identifier at the start

        # Encode the source_ip, dest_ip, and mode (these are still bytes)
        encoded_data += bytes([self.source_ip, self.dest_ip, self.mode])

        # Add the IP packet data (either already in bytes or we need to convert it to bytes)
        encoded_data += self.ip_packet

        # Add the MAC (always in bytes)
        encoded_data += self.mac

        return encoded_data

    @staticmethod
    def decode(packet_data):
        # Decode source IP, destination IP, and mode (all are bytes)
        source_ip = packet_data[1]  # First byte: source IP
        dest_ip = packet_data[2]  # Second byte: destination IP
        mode = packet_data[3]  # Third byte: mode
        # Extract MAC from the last 32 bytes
        received_mac = packet_data[-32:]  # Last 32 bytes are the MAC

        # Extract the IP packet data (everything between the source, dest, mode, and MAC)
        ip_packet_data = packet_data[4:-32]

        # Assuming IPSecPacket constructor expects the ip_packet_data and mac
        return IPSecPacket(source_ip, dest_ip, mode, ip_packet_data, received_mac)

    def __str__(self):
        """String representation for debugging"""
        return (
            f"IPSec[src=0x{self.source_ip:02X}, dst=0x{self.dest_ip:02X}, "
            f"mode={self.mode}, ip_packet={self.ip_packet}, mac={self.mac}]"
        )
