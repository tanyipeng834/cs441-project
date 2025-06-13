import sys
import atexit
# from models.node import Node
from models.spoofing_node import SpoofingNode
from utils.routing import R5_ARP_TABLE, R5_NETWORK

if __name__ == "__main__":
    # Create Node 1 with IP address 0x1A
    node = SpoofingNode("NA", 0x5A, 50010, R5_NETWORK, default_gateway="R5")

    # Initialize ARP table - Node1 only knows about itself and R1 in its network
    node.init_arp_table(R5_ARP_TABLE)  # Self  # Router interface R1

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
