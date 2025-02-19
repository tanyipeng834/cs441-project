import socket
import threading
import sys
from EthernetFrame import EthernetFrame
import traceback


class Node:
    MAX_DATA_LENGTH = 256
    HOST_IP = "127.0.0.1"
    BASE_PORT = 50000

    def __init__(self, mac_address, port, network):
        self.mac_address = mac_address
        self.port = port
        self.network = network

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Allow reusing the address to avoid "Address already in use" in quick restarts
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((Node.HOST_IP, self.port))
            self.sock.listen(1)
        except socket.error as e:
            print(f"Error starting node on port {self.port}: {e}")
            sys.exit(1)

        print(f"Node {self.mac_address} started on port {self.port}.")

        # Flag to control the listening loop
        self.is_running = True

        # Start a non-daemon thread to listen for incoming frames
        self.listen_thread = threading.Thread(target=self.listen_for_frames)
        self.listen_thread.start()

    def send_frame(self, destination, data):
        """
        Send a frame to all other nodes in the same network (Ethernet broadcast).
        Each node that receives it decides if it is the intended recipient or not.
        """
        for node in self.network.nodes:
            # Skip sending to itself
            if node == self:
                continue

            destination_port = self.process_node_mac(node.mac_address)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((Node.HOST_IP, destination_port))
                    frame = EthernetFrame(self.mac_address, destination, data)
                    s.sendall(frame.encode())
            except Exception as e:
                print(
                    f"Error sending frame from {self.mac_address} to {destination_port}: {e}"
                )

    def process_node_mac(self, mac_address):

        if mac_address[-2] == "R":

            port = Node.BASE_PORT + 3 + int(mac_address[-1])
        else:

            port = Node.BASE_PORT + int(mac_address[-1])
        return port

    def listen_for_frames(self):

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
            except Exception as e:
                print("Error in listen_for_frames:")
                traceback.print_exc()

    def process_frame(self, frame):

        if len(frame) < 5:
            print(f"Node {self.mac_address} received invalid frame: {frame}")
            return

        source = frame[0:2]
        destination = frame[2:4]
        data_length = ord(frame[4:5])
        data = frame[5 : 5 + data_length]

        if destination == self.mac_address:
            print(f"Node {self.mac_address} received data from {source}: {data}")
        else:
            print(
                f"Node {self.mac_address} dropped frame from {source} intended for {destination}"
            )

    def shutdown(self):

        self.is_running = False
        try:
            self.sock.close()
        except Exception as e:
            print(f"Error closing socket on port {self.port}: {e}")

        # Join the listening thread to ensure it finishes
        if self.listen_thread.is_alive():
            self.listen_thread.join()
