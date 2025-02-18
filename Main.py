from Node import Node
from Network import Network
import time

class Main:
    def __init__(self):
        """
        Initialize the networks and nodes, and add the nodes to the corresponding networks.
        """
        # Create two LAN networks
        self.lan_1 = Network()
        self.lan_2 = Network()
        
       
        self.node1 = Node('N1', 50001, self.lan_1)
        self.node2 = Node('N2', 50002, self.lan_2)
        self.node3 = Node('N3', 50003, self.lan_2)
        self.router_interface_1 = Node('R1', 50004, self.lan_1)
        self.router_interface_2 = Node('R2', 50005, self.lan_2)
        
      
        self.lan_1.add_node(self.node1)
        self.lan_1.add_node(self.router_interface_1)
        
        self.lan_2.add_node(self.node2)
        self.lan_2.add_node(self.router_interface_2)
        self.lan_2.add_node(self.node3)

    def run(self):
       
        print("\n" + "="*50)
        print("TEST 1: ETHERNET FRAME COMMUNICATION")
        print("Description: Testing basic Ethernet frame sending between nodes in same LAN")
        print("Expected: Node2 sends frame to Node3, Node3 receives, others drop")
        print("="*50 + "\n")
        self.node2.send_frame('N3', 'Hello World, Coming from N2')
        time.sleep(2)  # Allow time for processing
        
        print("\n" + "="*50)
        print("TEST 2: IP PING - SAME LAN")
        print("Description: Testing IP ping between nodes in the same LAN")
        print("Expected: Node2 pings Node3, Node3 replies, others drop packets")
        print("="*50 + "\n")
        # Single ping from Node2 to Node3
        self.node2.ping(0x2B, "Hello Node3 from Node2 via IP")
        time.sleep(2)  # Allow time for response
        
        print("\n" + "="*50)
        print("TEST 3: IP PING - CROSS LAN")
        print("Description: Testing IP ping between nodes in different LANs")
        print("Expected: Node1 pings Node2 through router interfaces")
        print("="*50)
        self.node1.ping(0x2A, "Hello Node2 from Node1 via IP")
        time.sleep(1)  # Allow time for response
        
        print("\n" + "="*50)
        print("TEST 4: BROADCAST TEST")
        print("Description: Testing that frames are properly broadcast within LANs")
        print("Expected: All nodes in LAN2 should receive the frame")
        print("="*50)
        self.node2.send_frame('N3', 'Broadcast test from Node2')
        time.sleep(1)  # Allow time for processing

    def shutdown(self):
      
        self.node1.shutdown()
        self.node2.shutdown()
        self.node3.shutdown()
        self.router_interface_1.shutdown()
        self.router_interface_2.shutdown()

if __name__ == "__main__":
    
    main_app = Main()
    
   
    main_app.run()
    
  
    main_app.shutdown()
