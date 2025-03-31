import sys
import atexit
from models.spoofing_node import SpoofingNode
from utils.routing import R1_ARP_TABLE, R1_NETWORK

if __name__ == "__main__":
    # Create Node 10 with IP address 0x1F
    node = SpoofingNode("NA", 0x1F, 50014, R1_NETWORK, default_gateway="R1")

    # Initialize ARP table - Node only knows about itself and R1 in its network
    node.init_arp_table(R1_ARP_TABLE)

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
