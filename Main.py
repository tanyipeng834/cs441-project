from Node import Node
from Network import Network
import time
from IPPacket import IP_ADDRESSES

class Main:
    def __init__(self):
        """
        Initialize the networks and nodes.
        Two networks:
        - LAN1: Node1 (0x1A) and Router interface R1 (0x11)
        - LAN2: Node2 (0x2A), Node3 (0x2B), and Router interface R2 (0x21)
        """
        # Create two LAN networks
        self.lan_1 = Network()
        self.lan_2 = Network()
        
       # Create nodes
        self.node1 = Node('N1', 50001, self.lan_1)
        self.node2 = Node('N2', 50002, self.lan_2)
        self.node3 = Node('N3', 50003, self.lan_2)
        self.router_interface_1 = Node('R1', 50004, self.lan_1)
        self.router_interface_2 = Node('R2', 50005, self.lan_2)
        
        # Add nodes to networks
        self.lan_1.add_node(self.node1)
        self.lan_1.add_node(self.router_interface_1)
        
        self.lan_2.add_node(self.node2)
        self.lan_2.add_node(self.router_interface_2)
        self.lan_2.add_node(self.node3)

    def test_ethernet(self):
        """Test basic Ethernet communication"""
        print("\n=== Testing Ethernet Communication ===")
        print("Test 1: Node2 sending to Node3 (same network)")
        self.node2.send_frame('N3', "Hello N3, this is N2")
        time.sleep(1)

        print("\nTest 2: Node1 sending to R1 (same network)")
        self.node1.send_frame('R1', "Hello R1, this is N1")
        time.sleep(1)

    def test_ping(self):
        """Test IP ping protocol"""
        print("\n=== Testing Ping Protocol ===")
        
        print("\nTest 1: Ping within same network (Node2 -> Node3)")
        print(f"Sending ping from {hex(IP_ADDRESSES['N2'])} to {hex(IP_ADDRESSES['N3'])}")
        self.node2.send_ping(IP_ADDRESSES['N3'])
        time.sleep(1)

        print("\nTest 2: Ping across networks (Node1 -> Node2)")
        print(f"Sending ping from {hex(IP_ADDRESSES['N1'])} to {hex(IP_ADDRESSES['N2'])}")
        self.node1.send_ping(IP_ADDRESSES['N2'])
        time.sleep(1)
        
    def test_multiple_pings(self):
        """Test multiple pings in sequence"""
        print("\n=== Testing Multiple Pings ===")
        
        # Node1 pings everyone
        print("\nNode1 pinging all other nodes:")
        self.node1.send_ping(IP_ADDRESSES['N2'])
        time.sleep(0.5)
        self.node1.send_ping(IP_ADDRESSES['N3'])
        time.sleep(0.5)

        # Node2 pings everyone
        print("\nNode2 pinging all other nodes:")
        self.node2.send_ping(IP_ADDRESSES['N1'])
        time.sleep(0.5)
        self.node2.send_ping(IP_ADDRESSES['N3'])
        time.sleep(0.5)

    def run_tests(self):
        """Run all tests"""
        try:
            # Give time for all nodes to start up
            time.sleep(1)
            
            # Run tests
            self.test_ethernet()
            time.sleep(1)
            
            self.test_ping()
            time.sleep(1)
            
            self.test_multiple_pings()
            time.sleep(1)

        except Exception as e:
            print(f"Error during tests: {e}")
        finally:
            # Give time for last messages to be processed
            time.sleep(2)
            self.shutdown()

    def shutdown(self):
        """Shutdown all nodes"""
        print("\n=== Shutting down all nodes ===")
        self.node1.shutdown()
        self.node2.shutdown()
        self.node3.shutdown()
        self.router_interface_1.shutdown()
        self.router_interface_2.shutdown()

if __name__ == "__main__":
    main_app = Main()
    main_app.run_tests()
