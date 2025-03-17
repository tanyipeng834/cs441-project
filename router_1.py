import sys
import atexit
from models.router import Router, RouterNode,BGPRouterNode

if __name__ == "__main__":
    # Create router with two nodes: R1 and R2
    # Node R1: connected to network with N1
    # Node R2: connected to network with N2 and N3

    # Create router nodes first
    r1_node = RouterNode("R1", 0x11, 50004, ["N1", "R1"])
    r2_node = RouterNode("R2", 0x21, 50005, ["N2", "N3", "R2"])
    r3_node = BGPRouterNode("R3",0x40,50006)
    
    
    

    # Create router with the nodes
    router = Router([r1_node, r2_node,r3_node])

    # Initialize network IPs for node R1
    r1_node.init_network_ips([0x1A])  # N1's IP is 0x1A
    # Initialize ARP table for node R1
    r1_node.init_arp_table(
        {0x1A: "N1", 0x11: "R1"}  # Map N1's IP to its MAC  # Self-reference
    )
    
    # Initialize network IPs for node R2
    r2_node.init_network_ips([0x2A, 0x2B])  # N2 and N3's IPs
    # Initialize ARP table for node R2
    r2_node.init_arp_table(
        {
            0x2A: "N2",  # Map N2's IP to its MAC
            0x2B: "N3",  # Map N3's IP to its MAC
            0x21: "R2",  # Self-reference
        
        }
    )


    # Initialize routing table
    router.init_routing_table(
        {
            
            0x1A: r1_node,  # Route to N1 via R1 node
            0x2A: r2_node,  # Route to N2 via R2 node
            0x2B: r2_node,  # Route to N3 via R2 node
            "*" : r3_node   # send to bgp interface to process extenral routes.
        }
    )

    r3_node.init_bgp_route({
        0x80 : [50007,"R4"]
    })

    
    # Register shutdown function to clean up on exit
    atexit.register(router.shutdown)

    print("Router started with nodes R1 (0x11) and R2 (0x21) and R3 (0x40)")
    print("Available commands:")
    print("  routes - Display the routing table")
    print("  arp - Display the ARP tables")
    print("  q - Exit")

    try:
        # Keep the main thread alive
        while True:
            command = input("Router>> ")
            if command.lower() == "q":
                print("Shutting down router...")
                break
            elif command.lower() == "routes":
                print("Routing table:")
                for ip, node in router.routing_table.items():
                    print(f"  0x{ip:02X} -> {node.mac_address}")
            elif command.lower() == "arp":
                print("ARP tables:")
                print("  R1 node:")
                for ip, mac in r1_node.arp_table.items():
                    print(f"    0x{ip:02X} -> {mac}")
                print("  R2 node:")
                for ip, mac in r2_node.arp_table.items():
                    print(f"    0x{ip:02X} -> {mac}")
            else:
                print("Unknown command. Available commands: routes, arp, q")
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Shutting down router...")
    finally:
        router.shutdown()
        sys.exit(0)
