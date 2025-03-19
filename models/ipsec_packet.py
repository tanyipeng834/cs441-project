from .ip_packet import IPPacket

class IPSecPacket:
    def __init__(self, source_ip, dest_ip, mode, ip_packet, mac):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.mode = mode  # 0 for AH, 1 for ESP
        self.ip_packet = ip_packet
        self.mac = mac  # MAC passed during initialization (if applicable)

    def encode(self):
    
        encoded_data = bytes([self.source_ip, self.dest_ip, self.mode])
        print(f"encoded data :{encoded_data}")
        print(f"ip_packet:{self.ip_packet}")
        print(f"mac:{self.mac}")
        # If mode is 1 (ESP mode), ip_packet is already bytes, otherwise, we need to convert it to bytes
        if self.mode == 1:
            # In ESP mode, ip_packet is already in bytes
            encoded_data += self.ip_packet
        else:
            #
            encoded_data += self.ip_packet.encode('utf-8')
        # Now, add the MAC (always in bytes)
        encoded_data += self.mac

        return encoded_data

    @staticmethod
    def decode(packet_data):
    # Decode source IP, destination IP, and mode (all are bytes)
        source_ip = packet_data[0]  # First byte: source IP
        dest_ip = packet_data[1]    # Second byte: destination IP
        mode = packet_data[2]       # Third byte: mode
        # Extract MAC from the last 32 bytes
        received_mac = packet_data[-32:]  # Last 32 bytes are the MAC
        
        
        # Extract the IP packet data (everything between the source, dest, mode, and MAC)
        ip_packet_data = packet_data[3:-32]
    
        
        # Assuming IPSecPacket constructor expects the ip_packet_data and mac
        return IPSecPacket(source_ip, dest_ip, mode, ip_packet_data, received_mac)

        
    def __str__(self):
        """String representation for debugging"""
        return (f"IPSec[src=0x{self.source_ip:02X}, dst=0x{self.dest_ip:02X}, "
                f"mode={self.mode}, ip_packet={self.ip_packet}, mac={self.mac}]")