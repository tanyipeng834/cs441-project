import sys
import atexit
from models.spoofing_node import SpoofingNode
from utils.routing import R1_ARP_TABLE, R1_NETWORK

if __name__ == "__main__":
    # Create Node 9 with IP address 0x1E
    node = SpoofingNode("N6", 0x1D, 50006, R1_NETWORK, default_gateway="R1")

    # Initialize ARP table - Node only knows about itself and R1 in its network
    node.init_arp_table(R1_ARP_TABLE)

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
