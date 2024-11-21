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
MAX_CVES = 5

MAX_THREADS = 16
open_ports = 0
open_lock = threading.Lock()
print_lock = threading.Lock()
request_lock = threading.Lock()

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

#TODO add support for more services
def grab_banner(s, service):
    try:
        if service == 'http' or service == 'https':
            s.send(b'GET /\n')
            banner = s.recv(REVC_SIZE).decode().strip().split('\n')[2]
            exp = re.search(r"(\S+)/([\d\.]+)", banner)
            return [banner, f"{exp.group(1)} {exp.group(2)}"] 
        
        else:
            banner = s.recv(REVC_SIZE).decode().strip()

            if service == 'ssh':
                exp = re.search(r"SSH-\S+-(\S+)_([\d\.p]+)", banner)
                return [banner, f"{exp.group(1)} {exp.group(2)}"]

            else:
                return [banner, None]

    except Exception as e:
        return [f"ERROR grabbing banner, \"{e}\"", None]

def check_cves(keywords):
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        params = {
            "keywordSearch": keywords,
            "resultsPerPage": MAX_CVES
        }

        with request_lock:
            response = requests.get(url, params=params)

        if response.status_code == 200:
            result = response.json()
            cves = ""
            for vuln in result["vulnerabilities"]:
                cve_id = vuln["cve"]["id"]
                description = vuln["cve"]["descriptions"][0]["value"] #assumes first description is in English
                cves += f"\n\t{cve_id}: {description}"
            return cves
        else:
            return "Found nothing"
    except Exception as e:
        return "Error getting CVEs"

def scan_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)

        #tcp connect scan
        result = s.connect_ex((target_ip, port))

        if result != 0:
            if args.v:
                with print_lock:
                    print(f"Port {port} is closed.")
            return False

        message = f"Port {port} is open."

        if args.s or args.b or args.v:
            service = get_service(s, port)
            if args.s:
                message += f"\n\tService: {service}"

            if args.b or args.c:
                banner = grab_banner(s, service)
                if args.b:
                    message += f"\n\tBanner: {banner[0]}"

                if args.c:
                    message += f"\n\tCVE(s): "
                    if banner[1] == None:
                        message += "Not enough info"
                    else: 
                        message += f"{check_cves(banner[1])}."

        with print_lock:
            print(message)
        return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', action='store_true', help='Get service, grab banner, and check for CVEs') #does all of the below
    parser.add_argument('-s', action='store_true', help='Get service running on port') #get's what service is running on the port
    parser.add_argument('-b', action='store_true', help='Banner grabbing') #get software banner information from the port
    parser.add_argument('-c', action='store_true', help='Check for CVEs (Warning: will considerably slow down scan)') #checks Common Vulnerabilites and Exposures (CVE)
    parser.add_argument('-v', action='store_true', help='Verbose mode (prints closed ports)') #print if a port is closed

    global args
    args = parser.parse_args()

    if args.a:
        args.s = True
        args.b = True
        args.c = True

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