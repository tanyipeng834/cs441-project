import sys
import atexit
from models.router_modules import Router, RouterInterface

if __name__ == "__main__":
    # Create router with two interfaces: R1 and R2
    # Interface R1: connected to network with N1
    # Interface R2: connected to network with N2 and N3
    
    # Create router interfaces first
    r1_interface = RouterInterface("R1", 0x11, 50004, ["N1", "R1"])
    r2_interface = RouterInterface("R2", 0x21, 50005, ["N2", "N3", "R2"])
    
    # Create router with the interfaces
    router = Router([r1_interface, r2_interface])
    
    # Initialize network IPs for interface R1
    r1_interface.init_network_ips([0x1A])  # N1's IP is 0x1A
    # Initialize ARP table for interface R1
    r1_interface.init_arp_table({
        0x1A: "N1",  # Map N1's IP to its MAC
        0x11: "R1"   # Self-reference
    })
    
    # Initialize network IPs for interface R2
    r2_interface.init_network_ips([0x2A, 0x2B])  # N2 and N3's IPs
    # Initialize ARP table for interface R2
    r2_interface.init_arp_table({
        0x2A: "N2",   # Map N2's IP to its MAC
        0x2B: "N3",   # Map N3's IP to its MAC
        0x21: "R2"    # Self-reference
    })
    
    # Initialize routing table
    router.init_routing_table({
        # This is just a minimal example - for more complex networks, add more routes
        0x1A: r1_interface,  # Route to N1 via R1 interface
        0x2A: r2_interface,  # Route to N2 via R2 interface
        0x2B: r2_interface   # Route to N3 via R2 interface
    })
    
    # Register shutdown function to clean up on exit
    atexit.register(router.shutdown)
    
    print("Router started with interfaces R1 (0x11) and R2 (0x21)")
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
                for ip, interface in router.routing_table.items():
                    print(f"  0x{ip:02X} -> {interface.mac_address}")
            elif command.lower() == "arp":
                print("ARP tables:")
                print("  R1 interface:")
                for ip, mac in r1_interface.arp_table.items():
                    print(f"    0x{ip:02X} -> {mac}")
                print("  R2 interface:")
                for ip, mac in r2_interface.arp_table.items():
                    print(f"    0x{ip:02X} -> {mac}")
            else:
                print("Unknown command. Available commands: routes, arp, q")
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Shutting down router...")
    finally:
        router.shutdown()
        sys.exit(0)