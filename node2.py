import sys
import atexit
from models.node import Node

if __name__ == "__main__":
    # Node 2
    node = Node("N2", 50002, ["N1", "N2", "N3", "R1", "R2"])
    atexit.register(node.shutdown)

    print("Please input your destination and data as two separate arguments.")
    print("Input 'q' to exit.")

    try:
        while True:
            user_input = input(">> ").strip()
            if user_input.lower() == "q":
                print("Exiting...")
                break
            if not user_input:
                continue

            parts = user_input.split(" ", 1)
            if len(parts) != 2:
                print("Invalid input. Please provide both destination and data.")
                continue

            destination, data = parts
            if destination not in Node.VALID_DESTINATION:
                print("Invalid input. Please provide a valid destination")
                continue

            node.send_frame(destination, data)
            print(f"Packet sent to {destination} with data: {data}")
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Exiting...")
    finally:
        node.shutdown()
        sys.exit(0)
