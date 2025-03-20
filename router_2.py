import sys
import atexit
from models.router import Router, RouterNode,BGPRouterNode
from models.ip_packet import IPPacket

if __name__ == "__main__":
    # Create router with two nodes: R1 and R2
    # Node R1: connected to network with N1
    # Node R2: connected to network with N2 and N3

    # Create router nodes first
    r4_node = RouterNode("R4",0x41,50007,["R4","R3"])
    r5_node = RouterNode("R5", 0x51, 50008, ["R5","N4"])
    # r6_node = RouterNode("R6", 0x61, 50008, ["R6","R7"])
   
    
    

    # Create router with the nodes
    router = Router([r4_node,r5_node])
    r4_node.init_network_ips([0x31])
    r4_node.init_arp_table(
        {0x31: "R3", 0x41: "R4",0x1A: "R3",0x2A:"R3",0x2B:"R3"}
    )

    # Initialize network IPs for node R1
    r5_node.init_network_ips([0x5A])  # N1's IP is 0x1A
    # Initialize ARP table for node R1
    r5_node.init_arp_table(
        {0x5A: "N4", 0x51: "R5",0x1A:"R4",0x2A:"R4",0x2B:"R4"}  # Map N1's IP to its MAC  # Self-reference
    )
    
    # Initialize network IPs for node R2
   

    # Initialize routing table
    router.init_routing_table(
        {
            
             0x5A: r5_node,  # Route to N1 via R1 node
             0x41: r4_node,
             0x1A: r4_node,
             0x2A: r4_node,
             0x2B :r4_node,

        }
    )

    

    
    # Register shutdown function to clean up on exit
    atexit.register(router.shutdown)

    atexit.register(router.shutdown)

    print("Router started with nodes R4 (0x41) and R5 (0x51) and R6 (0x61)")
    print("Available commands:")
    print("  routes - Display the routing table")
    print("  ipsec <mode> <ip> - Configure ipsec tunnel with another network")
    print("  ipsec off - Configure ipsec tunnel with another network")
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
                
                if len(args) ==2:
                    mode = args[0]
                    dest_ip= args[1]
                    # used with udp
                    source_ip = r3_node.ip_address
                    
                    dest_ip = int(dest_ip,16)
                    if dest_ip not in r4_node.network_ips:
                        print(" Network not available")
                    else:
                        ip_packet = IPPacket(source_ip,dest_ip,17,"IKE")
                        r4_node.send_ip_packet(ip_packet,dest_ip,r4_node.arp_table[dest_ip])
                        router.mutual_key_exchange(int(mode))
                    

                else:
                    if len(args) ==1:
                        ip_packet = IPPacket(source_ip,dest_ip,17,"IKE")
                        r4_node.send_ip_packet(ip_packet,dest_ip,r4_node.arp_table[dest_ip])
                        router.kill_tunnel()
                    else:
                        print("Error: Invalid command syntax. Usage: ipsec <mode> <ip> " )

            else:
                print("Unknown command. Available commands: routes, arp, q , ipsec")
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Shutting down router...")
    finally:
        router.shutdown()
        sys.exit(0)
