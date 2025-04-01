from models.node import Node
import queue
from models.ip_packet import IPPacket
from models.ping_protocol import PingProtocol
class TracebackNode(Node):
    """
    A node that has the capability to traceback attack from source.
    """

    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)
        # Log to store captured packets
        self.queue = queue.Queue(maxsize=100) 
        self.nodes ={}
        self.register_traceback_commands()
        

    def process_ip_packet(self, ip_packet: IPPacket):
        """Process a received IP packet"""
        if ip_packet.dest_ip == self.ip_address or ip_packet.dest_ip == 0xFF:
            print(
                f"  Received IP packet from 0x{ip_packet.source_ip:02X} to 0x{ip_packet.dest_ip:02X}"
            )
            
            print(f"  Protocol: {ip_packet.protocol}, Data length: {ip_packet.length}")
            
            if ip_packet.node is not None:
              
                ip_packet.node = int(ip_packet.node)
                
                if ip_packet.node not in self.nodes:
                    self.nodes[ip_packet.node] =1
                else:
                    self.nodes[ip_packet.node]+=1
            
            
                

            # Handle different protocols
            
            if ip_packet.protocol == PingProtocol.PROTOCOL:
                self.handle_ping_protocol(ip_packet)
            else:
                print(
                    f"  Unknown protocol: {ip_packet.protocol}, Data: {ip_packet.data}"
                )
        else:
            print(f"  Dropped IP packet intended for 0x{ip_packet.dest_ip:02X}")
    def add_ip_packet_to_queue(self, ip_packet: IPPacket):
        """Add an IP packet to the processing queue"""
        try:
            self.queue.put_nowait(ip_packet)
            current_size = self.queue.qsize()
            print(f"  Queue size: {current_size}/{self.queue.maxsize}")
        except queue.Full:

            print(f"  Queue full, dropping IP packet from 0x{ip_packet.source_ip:02X}")
            print(f" Initiate Ip Traceback to find the source of the attack.")
           

    def process_queue(self):
        """Process IP packets in the queue"""
        while self.is_running:
            # Add delay to simulate processing time
            self.sleep_event.wait(timeout=0.5)
            try:
                ip_packet = self.queue.get_nowait()
                if ip_packet:
                    self.process_ip_packet(ip_packet)
            except queue.Empty:
                pass
            except Exception:
                pass
                

    def ip_traceback(self):
        """Perform IP traceback to identify attack sources in DDoS attacks."""
        # Sort nodes by their counts (least encountered first)
        if len(self.nodes)==0:
            print ("No nodes to traceback yet.")
            return
        
        sorted_nodes = sorted(self.nodes.items(), key=lambda x: x[1])
    

        # Initialize a list to store the path
        traceback_path = []

        print("Performing IP Traceback...")

        # Build the path from the sorted nodes
        for node, count in sorted_nodes:
            print(f"Node {hex(node)} encountered {count} times.")
            traceback_path.append(hex(node))

        # Create a string representation of the path with "->" arrows
        traceback_string = " -> ".join(traceback_path)
        


        # Print the traceback path
        print(f"Traceback Path: {traceback_string}")
        

        return traceback_string
    def reset_nodes(self):
        """Reset the node count periodically."""
        self.nodes = {}
        return



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
                        # Do not add the queue and just process it straight away.
                        self.add_ip_packet_to_queue(ip_packet)

                    except Exception:
                        print(f"  Data: {data}")

            else:
                print(
                    f"Node {self.mac_address} dropped frame from {source_mac} intended for {destination_mac}"
                )

        except Exception as e:
            print(f"Error processing frame: {frame} - {e}")
    
    def register_traceback_commands(self):
        @self.command(
            "traceback", "- Use IP traceback to identify attack sources in DDoS attacks."
        )
        def cmd_traceback(self,args):
            self.ip_traceback()
            self.reset_nodes()

