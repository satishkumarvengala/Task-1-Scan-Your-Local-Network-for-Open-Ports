# Task-1-Scan-Your-Local-Network-for-Open-Ports
CYBER SECURITY INTERNSHIP
Run a simple nmap scan on local IP range

VirtualBox- Kali Machine 

STEP 1: Finding local IP range 
Command: ip a
<img width="987" height="466" alt="Image" src="https://github.com/user-attachments/assets/9f9d19a2-bdb1-4d9c-90d7-522a7b98e13b" />
Local IP range found under eth0 as 10.0.2.15/24

STEP 2: Open wireshark and keep ready for packet capture
<img width="646" height="152" alt="Image" src="https://github.com/user-attachments/assets/28388ede-a89b-405a-82c8-9c2c844836a5" />

STEP 3: Run the nmap command: nmap -sS 10.0.2.15/24
<img />

As we can see in the screenshot above the command requires sudo privileges.

Results:
Out of 256 possible hosts, 3 are active (responded)

On host 10.0.2.2 ports 135, 445, 3306, 7070, 9999 are open

On host 10.0.2.3 port 53 is open

On host 10.0.2.15 there are no open ports

STEP 4: Go to wireshark and monitor the packages 
<img  />
As we can see here the TCP handshake is taking place.

STEP 5: 
Save scan results in a text file for future reference.
<img  />

Additional Analysis:

Common services running in the open ports:
TCP 135 : Microsoft RPC / DCE-RPC (RPC Endpoint Mapper). Common on Windows hosts (RPC/DCOM/remote management).

TCP 445 :Microsoft-DS (SMB/CIFS) used for Windows file sharing, domain controller communication, named pipes, and many Windows services.

TCP 3306 : MySQL / MariaDB server (database).

TCP 7070 :Often used by streaming servers (RealServer / Helix / RTSP-like services) or custom apps; not standardized — application-specific.

TCP 9999 : Frequently used by web admin panels (Abyss web server uses 9999 by default), debug interfaces, or custom services. Highly variable.

TCP 53 : DNS (domain service) over TCP — used for zone transfers, large DNS responses, and when UDP fails.

Security Risks cause by open ports:

1) Unauthorized Access- 
Each open port represents a potential entry point into the system.
Attackers can connect to exposed services and try default or weak credentials.
If the service has poor authentication, they can gain access to files, databases, or even system control.

2) Exploitation of Vulnerabilities- 
Every running service (like SSH, SMB, or MySQL) may have known vulnerabilities (e.g., buffer overflows, RCE, privilege escalation).
Attackers scan networks to find systems with specific open ports and then exploit known CVEs associated with them.

3) Information Disclosure- 
Some services leak system details like OS version, hostname, usernames, or internal network structure.
Example: older FTP, HTTP, or SNMP services often reveal sensitive info useful for later attacks (reconnaissance phase).

4) Brute Force and Credential Attacks-
Open ports running login-based services (SSH, RDP, MySQL, etc.) are targets for password guessing or brute-force attacks.

5) Denial of Service (DoS)-
Attackers can flood open ports with traffic to overload a service, making it unavailable to legitimate users.

6) Privilege Escalation and Lateral Movement-
Once attackers gain access through one open service, they can move laterally across the network using other open ports (like SMB or RPC).
They might escalate privileges and compromise the entire system or domain.

7) Data Exfiltration-
Malicious actors can use open ports to send data out of the network without being noticed.
Example: attackers tunnel traffic through allowed ports (like 443 or 53) to exfiltrate data stealthily.

8) Malware and Botnet Infections-
Open, unpatched, or misconfigured services are common infection vectors.
Malware can exploit these ports to install itself and use the machine for spam, DDoS, or crypto mining.

9) Man-in-the-Middle (MitM) Attacks-
If communication over open ports isn’t encrypted (e.g., HTTP, Telnet, FTP), attackers can intercept and modify data in transit.



Questions

 1.What is an open port?
 
 An open port is a network port on a device that is actively listening for incoming connections.
 It indicates that a service or application is running and ready to communicate using a specific protocol (e.g., HTTP on port 80, SSH on port 22).
 
 2.How does Nmap perform a TCP SYN scan?
 
 Nmap sends a SYN packet (the first step in the TCP handshake).
 If the target replies with SYN-ACK, the port is open.
 If the target replies with RST, the port is closed.
 If there’s no response or an ICMP unreachable message, it’s filtered (by a firewall).
 Nmap then sends an RST to avoid completing the handshake, making the scan stealthier and faster.
 
 3.What risks are associated with open ports?
 
 (Covered above)
 
 4.Explain the difference between TCP and UDP scanning.
 
 TCP Scanning:
 Uses the Transmission Control Protocol (TCP) which is connection-oriented.
 Nmap sends SYN packets and checks how the target responds.
 If a SYN-ACK is received, the port is open.
 If an RST (Reset) is received, the port is closed.
 TCP scanning is generally faster, more reliable, and gives clearer results.
 Commonly used for services like HTTP (80), SSH (22), FTP (21), etc.
 
 UDP Scanning:
 Uses the User Datagram Protocol (UDP) which is connectionless.
 Nmap sends UDP packets (sometimes empty, sometimes protocol-specific).
 If there’s no response or a valid UDP reply, the port is considered open or open|filtered.
 If an ICMP “Port Unreachable” message is returned, the port is closed.
 UDP scanning is slower and less reliable, because many systems block ICMP replies.
 Commonly used for services like DNS (53), DHCP (67/68), SNMP (161), etc.
 
 5.How can open ports be secured?
 
 Closing unused ports to reduce attack surface.
 Using firewalls to limit access based on IP or network.
 Updating and patching all services regularly.
 Using encryption and authentication for exposed services (e.g., HTTPS, SSH).
 Running port scans regularly to detect unexpected open ports.
 
 6.What is a firewall's role regarding ports?
 
 It monitors ports and can block, allow, or filter traffic to specific ones.
 Firewalls help prevent unauthorized access by blocking unnecessary or suspicious connections.
 
 7.What is a port scan and why do attackers perform it?
 
 A port scan is the process of sending packets to a target to identify which ports are open, closed, or filtered.
 Attackers perform port scans to:
 Discover which services and applications are running on a target.
 Identify potential vulnerabilities for exploitation.
 Map the network and gather intelligence during reconnaissance.
 Ethical hackers also use it for vulnerability assessment and network hardening.
 
 8.How does Wireshark complement port scanning?
 
 Allowing users to see live packet exchanges during scans (e.g., SYN, SYN-ACK, RST).
 Helping verify how systems respond to probes from tools like Nmap.
 Detecting anomalies, dropped packets, or firewall interference.
