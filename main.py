import socket
import re
from datetime import datetime

def scan_port(target_ip, port):
     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1) 
        result = s.connect_ex((target_ip, port)) 

        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "Unknown service"
            print(f"Port {port} is open. Service: {service}")

def scan_range(target, port_range):
    print(f"\nStarting scan on target: {target}")
    print(f"Scanning ports {port_range[0]} to {port_range[1]}\n")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Unable to resolve hostname.")
        return
    
    start_time = datetime.now()

    for port in range(port_range[0], port_range[1] + 1):
        scan_port(target_ip, port)
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\nScan completed in: {duration}")

if __name__ == "__main__":
    print("--- Port Scanner ---")

    target = input("Enter the target hostname or IP: ").strip()
    default_ports = [21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]
    ports = default_ports

    try:
        ports_input = input(f"Enter ports to scan (inclusive range or comma-separated) or press Enter to use default ({default_ports}): ").strip()
        if ports_input:
            if re.match(r"^(\d*)\s*-\s*(\d*)$", ports_input):
                ports.clear()
                port_range = list(map(int, ports_input.split('-')))
                for i in range (port_range[0], port_range[1] + 1):
                    ports.append(i)
            else: 
                ports = list(map(int, ports_input.split(',')))
    except ValueError:
        print("Invalid input. Using default ports.")
        ports = default_ports

    scan_range(target, ports)