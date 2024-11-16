import socket
from datetime import datetime

def port_scanner(target, ports):
    print(f"\nStarting scan on target: {target}")
    print(f"Scanning specified ports: {ports}\n")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Unable to resolve hostname.")
        return

    start_time = datetime.now()

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1) 
            result = s.connect_ex((target_ip, port)) 

            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "Unknown service"
                print(f"Port {port} is open. Service: {service}")

    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\nScan completed in: {duration}")

if __name__ == "__main__":
    print("--- Port Scanner ---")

    target = input("Enter the target hostname or IP: ").strip()
    default_ports = [21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]

    try:
        ports_input = input(f"Enter ports to scan (comma-separated) or press Enter to use default ({default_ports}): ").strip()
        if ports_input:
            ports = list(map(int, ports_input.split(',')))
        else:
            ports = default_ports
    except ValueError:
        print("Invalid input. Using default ports.")
        ports = default_ports

    port_scanner(target, ports)
