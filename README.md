# About the Project 
This is a simple port scanner created for educational purposes using Ubuntu 22.04.4 VMs. It gets the following information 
- What ports are open 
- What service running on an open port (EX: http, ssh, etc.)
- Software banner from the service running 
- Common Vulnerabilites and Exposures (CVE) based on the banner
Please use NMap or other more sophisticated port scanners if you need a good port scanner. 

## Port Scanners 
Port scanning is a network security technique that reveals which ports are open along with other additional inforamtion. System admins use port scanning to check their own networks and security policies for vulnerabilities. Attackers can also use port scans to gain reconnaissance about the inner workings of a network if system admins are not diligent. 
There a several different types of port scanners. This project uses a TCP connect scan.  

## Services 
This project uses socket.getservbyport() which returns the service name associated with a port number. 

## Banner Grabbing 
Banner grabbing reveals information like the name and version of the network host. This project uses active banner grabbing to ideally isolate the name and version of the network host. 

## Common Vulnerabilites and Exposures (CVE)
Common Vulnerabilites and Exposures (CVE) is a list of known vulnerabilites. This project uses information gained from banner grabbing to seach the NIST's CVE API (https://nvd.nist.gov/developers/vulnerabilities). Currently, it is really only effective when the service is http or OpenSSH is used. 

# Getting Started 
## Prerequisites 
Please make sure you have python installed and the following Python modules 
- socket
- re
- argparse
- threading
- concurrent.futures
- requests

## Optional 
You can open ports using nc to test the port scanners ability to check if a port is open using
`sudo nc -lk 100` 
### Damn Vulnerable Web Application (DVWA)
You can set up Damn Vulnerable Web Application (DVWA) to test the port scanner. Do the following to create and start DVWA on port 80: 
```bash
sudo apt update
sudo apt install docker.io docker-compose -y
sudo docker pull vulnerables/web-dvwa
sudo docker run -p 80:80 vulnerables/web-dvwa
```
### Vulhub 
Vulhub has multiple pre-built vulnerable docker enviornments that you can also use to test the port scanner. 
To set up, please following the instructions at: https://github.com/vulhub/vulhub 

# Usage 
*Only use this port scanner on computers you have permission to scan.* 

## Command Line Arguments 
This scanner has the following options 
  -h, --help  show this help message and exit
  -a          Flag for all
  -s          Get service running on port
  -b          Banner grabbing
  -c          Check for CVEs
  -v          Verbose mode (prints closed ports)

## Examples 
Here are some examples of the 4240-port-scanner in action: 

```bash
$ python3 main.py
--- Port Scanner ---
Enter the target hostname or IP: 10.0.2.15
Enter ports to scan (inclusive range or comma-separated) or press Enter to use default ([21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]):


Starting scan on target: 10.0.2.15
Scanning ports ...

Port 80 is open.

Scan completed in: 0:00:00.010391. Scanned 16 ports, found 1 open.
```

```bash
$ python3 main.py -s
--- Port Scanner ---
Enter the target hostname or IP: 10.0.2.15
Enter ports to scan (inclusive range or comma-separated) or press Enter to use default ([21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]):
1-65535

Starting scan on target: 10.0.2.15
Scanning ports ...

Port 80 is open.
    Service: http
Port 34276 is open.
    Service: Unknown service

Scan completed in: 0:00:03.903776. Scanned 65535 ports, found 2 open.
```

```bash
$ python3 main.py -a
--- Port Scanner ---
Enter the target hostname or IP: 10.0.2.15
Enter ports to scan (inclusive range or comma-separated) or press Enter to use default ([21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]):
80

Starting scan on target: 10.0.2.15
Scanning ports ...

Port 80 is open.
	Service: http
	Banner: Apache 2.4.25
	CVE(s): 
	CVE-2017-7659: A maliciously constructed HTTP/2 request could cause mod_http2 in Apache HTTP Server 2.4.24, 2.4.25 to dereference aNULL pointer and crash the server process.
	CVE-2016-8743: Apache HTTP Server, in all releases prior to 2.2.32 and 2.4.25, was liberal in the whitespace accepted from requests and sent in response lines and headers. Accepting these different behaviors represented a security concern when httpd participates in any chain of proxies or interacts with back-end application servers, either through mod_proxy or using conventional CGI mechanisms, and may result in request smuggling, response splitting and cache pollution.
	CVE-2016-4975: Possible CRLF injection allowing HTTP response splitting attacks for sites which use mod_userdir. This issue was mitigated by changes made in 2.4.25 and 2.2.32 which prohibit CR or LF injection into the "Location" or other outbound header key or value. Fixed in Apache HTTP Server 2.4.25 (Affected 2.4.1-2.4.23). Fixed in Apache HTTP Server 2.2.32 (Affected 2.2.0-2.2.31).

Scan completed in: 0:00:03.525605. Scanned 1 ports, found 1 open.
```

```bash
$ python3 main.py -sb
--- Port Scanner ---
Enter the target hostname or IP: scanme.nmap.org
Enter ports to scan (inclusive range or comma-separated) or press Enter to use default ([21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]):
20-150

Starting scan on target: scanme.nmap.org
Scanning ports ...

Port 22 is open.
	Service: ssh
	Banner: OpenSSH 6.6.1p1
Port 80 is open.
	Service: http
	Banner: Apache 2.4.7

Scan completed in: 0:00:29.131985. Scanned 131 ports, found 2 open.
```

# Acknowledgements/ References
- https://nmap.org/ 
- https://nvd.nist.gov/developers/vulnerabilities
- https://hub.docker.com/r/vulnerables/web-dvwa 
- https://www.geeksforgeeks.org/what-is-banner-grabbing/
- https://github.com/vulhub/vulhub 