import socket
from datetime import datetime

def port_scanner(target, port_range):
    print(f"\nStarting scan on target: {target}")
    print(f"Scanning ports {port_range[0]} to {port_range[1]}\n")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Unable to resolve hostname.")
        return

    start_time = datetime.now()

    for port in range(port_range[0], port_range[1] + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target_ip, port)) 

            if result == 0:
                print(f"Port {port} is open.")

    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\nScan completed in: {duration}")

if __name__ == "__main__":
    print("--- Port Scanner ---")

    target = input("Enter the target hostname or IP: ").strip()
    port_range = (1, 1024) 

    try:
        port_range_input = input("Enter port range (e.g., 1-1024) or press Enter to use default: ").strip()
        if port_range_input:
            start_port, end_port = map(int, port_range_input.split('-'))
            port_range = (start_port, end_port)
    except ValueError:
        print("Invalid port range input. Using default range.")

    port_scanner(target, port_range)
