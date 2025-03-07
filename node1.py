import sys
import atexit
from models.spoofing_node import SpoofingNode

if __name__ == "__main__":
    # Create Node 1 with IP address 0x1A
    node = SpoofingNode("N1", 0x1A, 50001, ["N1", "R1"], default_gateway="R1")

    # Initialize ARP table - Node1 only knows about itself and R1 in its network
    node.init_arp_table({0x1A: "N1", 0x11: "R1"})  # Self  # Router interface R1

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
