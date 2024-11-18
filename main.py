import socket
import re
import argparse
import threading
import concurrent.futures
import requests
from datetime import datetime

TIMEOUT = 5
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]
REVC_SIZE = 1024

MAX_THREADS = 16
open_ports = 0 
open_lock = threading.Lock()
print_lock = threading.Lock()


def scan_port_wrapper(port):
    if scan_port(port):
        global open_ports
        with open_lock:
            open_ports += 1


def get_service(s, port):
    try:
        return socket.getservbyport(port)
    
    except OSError:
        return "Unknown service"

def grab_banner(s, port):
    try:
        protocol = get_service(s, port)

        if protocol == 'http' or protocol == 'https':
            s.send(b'GET /\n')
            return s.recv(REVC_SIZE).decode().strip().split('\n')[2]
        
        #TODO add cases for other protocols
        
        else:
            return s.recv(REVC_SIZE).decode().strip()
    
    except Exception as e:
        return f"ERROR grabbing banner, \"{e}\""

def check_cves(s, port):
    #TODO: should check the port for any common vulnerabilites and exposures (CVE)
    #I know there's several libraries, external databases, APIs out there (PyCVESearch, NVD, CVE, Shodan, Vulners, nmap, etc)
    #But I haven't gotten them to work
    pass 

def scan_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)

        #tcp connect scan
        result = s.connect_ex((target_ip, port))

        if result != 0:
            #with print_lock:
            #    print(f"Port {port} is closed.")
            return False

        message = f"Port {port} is open."

        if args.s:
            message += f"\n\tService: {get_service(s, port)}."

        if args.b:
            message += f"\n\tBanner: {grab_banner(s, port)}."

        if args.v:
            message += f"\n\tCVE(s): {check_cves(s, port)}."

        with print_lock:
            print(message)
        return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', action='store_true', help='flag for all')
    parser.add_argument('-s', action='store_true', help='flag for getting the service')
    parser.add_argument('-b', action='store_true', help='flag for banner grabbing')
    parser.add_argument('-v', action='store_true', help='flag to check for CVEs')

    global args 
    args = parser.parse_args()

    if args.a:
        args.s = True
        args.b = True
        args.v = True

    print("--- Port Scanner ---")

    target = input("Enter the target hostname or IP: ").strip()
    ports = DEFAULT_PORTS

    try:
        ports_input = input(f"Enter ports to scan (inclusive range or comma-separated) or press Enter to use default ({DEFAULT_PORTS}):\n").strip()
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
        ports = DEFAULT_PORTS

    print(f"\nStarting scan on target: {target}")

    try:
        global target_ip 
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Unable to resolve hostname.")
        exit()

    print(f"Scanning ports ...\n")
    start_time = datetime.now()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        result = executor.map(scan_port_wrapper, ports)

    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\nScan completed in: {duration}. Scanned {len(ports)} ports, found {open_ports} open.")