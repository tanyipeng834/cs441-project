import socket
import threading
import sys
from EthernetFrame import EthernetFrame
import traceback
class Node:
    MAX_DATA_LENGTH = 256
    HOST_IP = '127.0.0.1'
    BASE_PORT = 50000
    def __init__(self, mac_address, port,network):
        self.mac_address = mac_address
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.bind((Node.HOST_IP, self.port))
            self.sock.listen(1)
        except socket.error as e:
            print(f"Error starting node on port {self.port}: {e}")
            sys.exit(1)
        self.network = network
        print(f"Node {self.mac_address} started on port {self.port}.")
        
        # Start a thread to listen for incoming frames
        threading.Thread(target=self.listen_for_frames, daemon=True).start()

    def send_frame(self, destination, data):
        # Ethernet broadcast
        for node in self.network.nodes:
            
            # Skip if it is the same node as itself, as we do not want to send 
            # to ourselves
            if node == self:
                continue
            else:
                
                destination_port = self.process_node_mac(node.mac_address)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((Node.HOST_IP, destination_port))
                    frame = EthernetFrame(self.mac_address,destination,data)
                    
                    s.sendall(frame.encode())


    def process_node_mac(self,mac_address):
        if mac_address[-2] =='R':
            port = Node.BASE_PORT + 3 + int(mac_address[-1])
        else:
            port = Node.BASE_PORT + int(mac_address[-1])
        return port



   

    def listen_for_frames(self):
        while True:
            try:
                conn, addr = self.sock.accept()
               
                with conn:
                    frame = conn.recv(2 + 2 + 1 + Node.MAX_DATA_LENGTH).decode('utf-8')
                    self.process_frame(frame)
            except Exception as e:
                print("Error in listen_for_frames:")
                traceback.print_exc()  # This will print the full traceback of the exception


    def process_frame(self, frame):
        
        source = frame[0:2]
        destination = frame[2:4]  
        data_length = ord(frame[4:5])
        data = frame[5:5+data_length]
        if destination == self.mac_address:
            print(f"Node {self.mac_address} received data from {source}: {data}")
        else:
            print(f"Node {self.mac_address} dropped frame from {source} intended for {destination}")