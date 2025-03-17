import sys
import atexit
from models.router import Router, RouterNode,BGPRouterNode
from models.ip_packet import IPPacket

if __name__ == "__main__":
    # Create router with two nodes: R1 and R2
    # Node R1: connected to network with N1
    # Node R2: connected to network with N2 and N3

    # Create router nodes first
   
    r4_node = BGPRouterNode("R4",0x80,50007)
    r5_node = RouterNode("R5", 0x11, 50008, ["N4"])
    
    
    

    # Create router with the nodes
    router = Router([r4_node,r5_node])

    # Initialize network IPs for node R1
    r5_node.init_network_ips([0x1A])  # N1's IP is 0x1A
    # Initialize ARP table for node R1
    r5_node.init_arp_table(
        {0x1A: "N4", 0x11: "R4"}  # Map N1's IP to its MAC  # Self-reference
    )
    
    # Initialize network IPs for node R2
   

    # Initialize routing table
    router.init_routing_table(
        {
            
            0x1A: r5_node,  # Route to N1 via R1 node
            "*" : r4_node
        }
    )

    r4_node.init_bgp_route({
        0x40 : [50006,"R3"]
    })

    
    # Register shutdown function to clean up on exit
    atexit.register(router.shutdown)

    print("Router started with nodes R1 (0x11) and R2 (0x21) and R3 (0x40)")
    print("Available commands:")
    print("  routes - Display the routing table")
    print("  ipsec <ip> - Configure ipsec tunnel with another network")
    print("  arp - Display the ARP tables")
    print("  q - Exit")

    try:
        # Keep the main thread alive
        while True:
            user_input = input("Router>> ")
            parts = user_input.split(" ")
            command = parts[0]
            args = parts[1:]

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
            elif command.lower() =="ipsec":
                
                if len(args) ==1:
                    dest_ip = args[0]
                    
                    # used with udp
                    source_ip = r4_node.ip_address
                    print(source_ip)
                   
                    dest_ip = int(dest_ip,16)
                    
                    if dest_ip not in r4_node.network_ips:
                        print("Network not in routing table")
                    else:
                        
                        ipsec_key_packet = IPPacket(source_ip,dest_ip,17,"IKE")
                        
                        r4_node.send_ip_packet(ipsec_key_packet,r4_node.network_ips[dest_ip][0],r4_node.network_ips[dest_ip][1])
                        router.mutual_key_exchange(dest_ip)
                else:
                    print("Error: Invalid command syntax. Usage: ipsec <ip>")
            else:
                print("Unknown command. Available commands: routes, arp, q, ipsec")
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Shutting down router...")
    finally:
        router.shutdown()
        sys.exit(0)
