import sys
import atexit
from models.smurf_node import SmurfNode
from utils.routing import R1_ARP_TABLE, R1_NETWORK

if __name__ == "__main__":
    # Create Node 1 with IP address 0x1A
    node = SmurfNode("N4", 0x1B, 50004, R1_NETWORK, default_gateway="R1")

    # Initialize ARP table - Node1 only knows about itself and R1 in its network
    node.init_arp_table(R1_ARP_TABLE)

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
