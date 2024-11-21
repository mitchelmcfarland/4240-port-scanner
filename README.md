# About the Project 
This is a simple port scanner created for educational purposes using Ubuntu 22.04.4 VMs. It gets the following information 
- What ports are open 
- What service running on an open port (EX: http, ssh, etc.)
- Software banner from the service running 
- Common Vulnerabilites and Exposures (CVE) based on the banner
Please use NMap or other more sophisticated port scanners if you need a good port scanner. 

## Port Scanners 
Port scanning is a network security technique that reveals which ports are open along with other additional inforamtion. System admins use port scanning to check their own networks and security policies for vulnerabilities. Attackers can also use port scans to gain reconnaissance about the inner workings of a network if system admins are not diligent. 
There a several different types of port scanners. This project uses a vanilla scan.  

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

```
$ python3 main.py
--- Port Scanner ---
Enter the target hostname or IP: 10.0.2.15
Enter ports to scan (inclusive range or comma-separated) or press Enter to use default ([21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]):


Starting scan on target: 10.0.2.15
Scanning ports ...

Port 21 is open.
Port 80 is open.

Scan completed in: 0:00:00.022371. Scanned 16 ports, found 2 open.
```

```
$ python3 main.py -s
--- Port Scanner ---
Enter the target hostname or IP: 10.0.2.15
Enter ports to scan (inclusive range or comma-separated) or press Enter to use default ([21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]):
0-65535

Starting scan on target: 10.0.2.15
Scanning ports ...

Port 21 is open.
	Service: ftp
Port 80 is open.
	Service: http
Port 55846 is open.
	Service: Unknown service

Scan completed in: 0:00:03.585883. Scanned 65536 ports, found 3 open.
```

```
$ python3 main.py -a
--- Port Scanner ---
Enter the target hostname or IP: 10.0.2.15
Enter ports to scan (inclusive range or comma-separated) or press Enter to use default ([21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]):
80

Starting scan on target: 10.0.2.15
Scanning ports ...

Port 80 is open.
	Service: http
	Banner: Server: Apache/2.4.25 (Debian)
	CVE(s): 
	CVE-2017-7659: A maliciously constructed HTTP/2 request could cause mod_http2 in Apache HTTP Server 2.4.24, 2.4.25 to dereference a NULL pointer and crash the server process.
	CVE-2016-8743: Apache HTTP Server, in all releases prior to 2.2.32 and 2.4.25, was liberal in the whitespace accepted from requests and sent in response lines and headers. Accepting these different behaviors represented a security concern when httpd participates in any chain of proxies or interacts with back-end application servers, either through mod_proxy or using conventional CGI mechanisms, and may result in request smuggling, response splitting and cache pollution.
	CVE-2016-4975: Possible CRLF injection allowing HTTP response splitting attacks for sites which use mod_userdir. This issue was mitigated by changes made in 2.4.25 and 2.2.32 which prohibit CR or LF injection into the "Location" or other outbound header key or value. Fixed in Apache HTTP Server 2.4.25 (Affected 2.4.1-2.4.23). Fixed in Apache HTTP Server 2.2.32 (Affected 2.2.0-2.2.31)..

Scan completed in: 0:00:00.589670. Scanned 1 ports, found 1 open.
```

```
$ python3 main.py -sb
--- Port Scanner ---
Enter the target hostname or IP: scanme.nmap.org
Enter ports to scan (inclusive range or comma-separated) or press Enter to use default ([21, 22, 23, 25, 53, 80, 443, 8080, 8443, 137, 139, 445, 1433, 1434, 3306, 3389]):
20-150

Starting scan on target: scanme.nmap.org
Scanning ports ...

Port 22 is open.
	Service: ssh
	Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
Port 80 is open.
	Service: http
	Banner: Server: Apache/2.4.7 (Ubuntu)

Scan completed in: 0:00:22.757996. Scanned 131 ports, found 2 open.
```

# TODOs 
- Update port scan to check if port is open, closed, or filtered 
- Update grab_banner so it works for more types of services 
- Update get_service so it can more accurately get port services 
- Update CVE look up and banner parsing to use Common Platform Enumeration (CPE) instead of keywords. Right now CVE look up is missing a few CVE's that should be there.

# Acknowledgements/ References
- https://nmap.org/ 
- https://nvd.nist.gov/developers/vulnerabilities
- https://hub.docker.com/r/vulnerables/web-dvwa 
- https://www.geeksforgeeks.org/what-is-banner-grabbing/