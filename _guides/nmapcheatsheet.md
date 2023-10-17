---
layout: default
tags: cheatsheet nmap portscan
---

# Nmap Cheat Sheet	
> nmap help screen\
> -h

```
nmap -h
```
 
## Nmap Scan Types
> TCP SYN port scan (Default)\
> -sS

```
nmap -sS target_host
```

> TCP connect port scan (Default without root privilege)\
> -sT	

```
nmap -sT target_host
```

> UDP port scan\
> -sU	

```
nmap -sU target_host	
```

> TCP ACK port scan\
> -sA	

```
nmap -sA target_host	
```

> TCP Window port scan (TCP ACK scan that take advantage of RST return) <sup>1</sup>\
> -sW	

```
nmap -sW target_host	
```

> TCP Maimon port scan (Scan invented Uriel Maimon) <sup>2</sup>\
> -sM	

```
nmap -sM target_host	
```

> TCP Idle Scan (Antirez's bind port scan) <sup>3</sup>\
> -sI	

```
nmap -sI zombie_host target_host	
```

> IP protocol scan (Determine which IP protocols are being used by the host)\
> -sO	

```
nmap -sO target_host	
```

> TCP NULL port scan (Flag Header is 0)\
> -sN	

```
nmap -sN target_host	
```

> TCP FIN port scan\
> -sF	

```
nmap -sF target_host	
```

> TCP Xmas port scan (FIN, PSH, URG flags)\
> -sX	

```
nmap -sX target_host	
```

> SCTP INIT ping scan (Use new layer 4 SCTP protocol) <sup>4</sup>\
> -sY	

```
nmap -sY target_host	
```

> Custom Scan Type\
> --scanflags  URG | ACK | PSH | RST | SYN | FIN | SYNFIN | etc

```
nmap --scanflags  FLAG	
```
<sup>1</sup> RST is returned. It does this by examining the TCP Window value of the RST packets returned: 

| Description                                                 | Status          |
|:------------------------------------------------------------|:----------------| 
| TCP RST response with non-zero window field                 | open            |
| TCP RST response with zero window field                     | closed          |
| No response received (even after retransmissions)           | filtered        |	     
| ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) | filtered        |

[source](https://nmap.org/book/scan-methods-window-scan.html)

<sup>2</sup> Uriel Maimon described the technique in Phrack Magazine issue #49 (November 1996). This technique is exactly the same as NULL, FIN, and Xmas scan, except that the probe is FIN/ACK. System should report if a port is open of close as stated in RPC 793 but Uriel noticed that many BSD systems drop the packet. While this option was quite useful in 1996, modern systems rarely exhibit this bug. They send a RST back for all ports, making every port appear closed.[source](https://nmap.org/book/scan-methods-maimon-scan.html) 

<sup>3</sup> Antirez's idle scan, aka bind port scan, can actually scan a target without sending a single packet to the target from their own IP address. A clever side-channel attack allows for the scan to be bounced off a dumb “zombie host”. This means any IDS will report the zombie host as the attacker instead of the host scanning the network. See URL for more info: https://nmap.org/book/idlescan.html [source](https://nmap.org/book/idlescan.html)

<sup>4</sup> Stream Control Transmission Protocol (SCTP) is a protocol that was designed for streaming services and other services that need real time communication. This also adds new features like multi-homing and multi-streaming compared to TCP and UDP. The INIT packet is similar to SYN TCP packet. See RFC for more information on this protocol [source](https://www.rfc-editor.org/rfc/rfc4960.txt)

## Network Discovery options

> No Scan. List targets only\
> -sL	

```
nmap -sL target_host	
```

> Disable port scanning. Host discovery only.\
> -sn	

```
nmap -sn target_host	
```

> Disable port scanning. Host discovery only. (Old flag)\
> -sP	

```
nmap -sP target_host	
```

> Disable host discovery. Port scan only.\
> -Pn	

```
nmap -Pn target_host	
```

> TCP SYN discovery on port x. Port 80 by default\
> -PS	

```
nmap -PSport-port,port target_host	
```

> TCP ACK discovery on port x.Port 80 by default\
> -PA	

```
nmap -PAport-port,port target_host	
```

> UDP discovery on port x.Port 40125 by default\
> -PU	

```
nmap -PUport target_host	
```

> ARP discovery on local network\
> -PR	

```
nmap -PR target_host	
```

> Never do DNS resolution\
> -n	

```
nmap -n target_host	
```

## Nmap Target Specification
> Single IP

```
nmap xx.xx.xx.xx
```

> Multiple IPs

```
 nmap xx.xx.xx.xx xx.xx.xx.xx ...
```

> Scan with a range

```
 nmap xx.xx.xx.xx-xx
```

> Scan with CIDR

```
 nmap xx.xx.xx.xx/xx
```

> Scan a domain

```
 nmap justanothernode.com
```

> Scan targets from a file\
> -iL	

```
nmap -iL ip_list_file.txt	
```

> Scan random host (num_host for how many)\
> -iR	

```
nmap -iR num_host	
```

> Exclude hosts\
> --exclude	

```
nmap --exclude excluded_host	
```


## Nmap Port Specification

> port scan for a single port, a range, UDP/TCP specification, and service names\
> -p	

```
nmap -p port,port-port,U:53,T20-22,http,https target_host	
```

> port scan all ports\
> -p-	

```
nmap -p- target_host	
```

> fast port scan (scan 100 ports)\
> -F	

```
nmap -F target_host
```

## Nmap OS and Version Detection

> Remote OS detection using TCP/IP fingerprinting\
> -O	

```
nmap -O target_host	
```

> If can not find one open and closed port, will not try\
> -O --osscan-limit	

```
nmap -O --oscan-limit target_host	
```

> Makes Nmap guess more aggressively\
> -O --osscan-guess	

```
nmap -O --oscan-guess target_host	
```

> Set max tries for OS detection\ 
> -O --max-os-tries	

```
nmap -O --max-os-tries num	
```

> Determine version of the services running on ports\
> -sV	

```
nmap -sV target_host		
```

> Intensity level of guessing services\
> -sV --version-intensity	

```
nmap -sV --version-intensity 0-9 target_host	
```

> Lowest possible guessing for services (Faster)\
> -sV --version-light	

```
nmap -sV --version-light target_host	
```

> Highest possible guessing for services (most correct)\
> -sV --version-all	

```
nmap -sV --version-all target_host
```

> OS detection, version detection, script scanning, and traceroute\
> -A

```
nmap -A target_host	
```

## Nmap Timing

> Paranoid (0) Intrusion Detection System evasion\
> -T0 

```
nmap -T0 target_host	
```
> Sneaky (1) Intrusion Detection System evasion\
> -T1

```
nmap -T1 target_host	
```
> Polite (2) slows down the scan to use less bandwidth and use less target machine resources\
> -T2 

```
nmap -T2 target_host	
```

> Normal (3) which is default speed\
> -T3	

```
nmap -T3 target_host	
```

> Aggressive (4) speeds scans; assumes you are on a reasonably fast and reliable network\
> -T4	

```
nmap -T4 target_host	
```

> Insane (5) speeds scan; assumes you are on an extraordinarily fast network\
> -T5	

```
nmap -T5 target_host
```

#### Nmap Timing Flags

> Give up on target after this long\
> --host-timeout time	

```
nmap --host-timeout time target host
```

> Specifies probe round trip time\
> --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout time	

```
nmap --mim-rtt-timeout time target_host
```
```
nmap --max-rtt-timeout time target_host
```
```
nmap --initial-rtt-timeout time target_host
```

> Parallel host scan group sizes\
> --min-hostgroup/max-hostgroup size

```
nmap --min-hostgroup size target_host
```
```
nmap --max-hostgroup size target_host
```

> Probe parallelization\
> --min-parallelism/max-parallelism num

```
nmap --min-parallelism num target_host	
```
```
nmap --max-parallelism num target_host
```

> Specify the maximum number of port scan probe retransmissions\
> --max-retires tries	

```
nmap --max-retires tries target_host
```

> Send packets no slower than num per second\
> --min-rate num	

```
nmap --min-rate num target_host
```

> Send packets no faster than num per second\
> --max-rate num	

```
nmap --max-rate num target_host
```

## Firewall/IDS Evasion and Spoofing

> Fragmented IP packets (Harder for packets to be filtered)\
> -f	

```
nmap -f target_host	
```

> Set the mtu\
> --mtu	

```
nmap --mtu num target_host	
```

> Send scans from spoofed IPs with your legit IP\
> -D	

```
nmap -D decoy-ip1,decoy-ip2,your-own-ip,decoy-ip3,decoy-ip4 remote-host-ip	
```

> Spoof source IP address\
> -S	

```
nmap -S source_host target_host	
```

> Set source port number\
> -g	

```
nmap -g port target_host	
```

> include binary data as payload to the packets\
> --data	

```
nmap --data hex_string target_host	
```

> include string stat as payload to the packets\
> --data-string	

```
nmap --data-string string target_host	
```

> Appends random data to sent packets\
> --data-length	

```
nmap –data-length num target_host	
```

> Send packets with specified ip options\
> --ip-option	

```
nmap --ip-option hex_string target_host	
```

> Set time to live\
> --ttl	

```
nmap --ttl num target_host	
```

> Spoof MAC address\
> --spoof-mac	

```
nmap --spoof-mac mac_addr,prefix,vendor target_host	
```

> Randomize target host order\
> --randomize-hosts	

```
nmap --randomize-hosts target_host	
```

> Send packets with bogus checksums (can bypass some firewalls/IDS because assume dropping the packet)\
> --badsum	

```
nmap --badsum target_host	
```

> Relay connections through HTTP/SOCKS4 proxies\
> --proxies	

```
nmap --proxies URL/IP	
```

## Nmap output

> Normal nmap output to file\
> -oN	

```
nmap -oN file.txt target_host	
```

> nmap output in XML format to file\
> -oX	

```
nmap -oX file.xml target_host	
```

> nmap output in grepable format to file\
> -oG	
```
nmap -oG file.gp target_host	
```

> nmap output to grepable to screen for piping (also -oN- and -oX- are allowed)\
> -oG -	

```
nmap target_host -oG-	
```

> Append a scan to a file\
> --append-output	

```
nmap -oN file.txt --append-output target_host	
```

> Increase the verbosity level\
> -v	

```
nmap -vvvv target_host	
```

> Increase the debugging level\
> -d	

```
nmap -dddd target_host	
```

> Display the reason for a port state\
> --reason	

```
nmap --reason target_host	
```

> Show all possible open ports only\
> --open	

```
nmap --open target_host	
```

> Show all packets sent and received\
> --packet-trace	

```
nmap --packet-trace target_host	
```

> Show the host interface and routes\
> --iflist	

```
nmap --iflist target_host	
```

> Resume a scan that had a output file\
> --resume	

```
nmap --resume target file.txt	
```

## Nmap NSE Scripts

> Scan with default NSE "safe" scripts (also can use --script default)\ 
> -sC	

```
nmap -sC target_host	
```

> Use single script, use wildcard * or comma for multiple\
> --script	

```
nmap --script=name_of_script target_host	
```

> Same as default scripts but removed "intrusive" scripts\
> --script "not intrusive"	

```
nmap --script "not intrusive" target_host	
```

> NSE script with arguments\
> --script-args	

```
nmap --script script_here --script-args scriptArgs=arg target_host	
```

> Get the arguments\
> --script-help 	

```
nmap --script-help script_name	
```

> Unix system default location for script (on most systems):\
> /usr/share/nmap/scripts/

## Nmap IPv6

> scan with for IPv6 addresses\
> -6	

```
nmap -6 target_host	
```

> scan IPv6 multicast addresses

```
nmap --script=ipv6-multicast-mld-list	
```


## Layer 2 Network Discovery Scans (ARP ping scan)
 
```
nmap -n -sn -PR --packet-trace --send-eth
```
> Layer 2 Network Discovery Scan Output to a File

```
nmap -n -sn -PR --packet-trace --send-eth target_host -oG - | grep -o '^[^#]*' | cut -d ':' -f 2 | cut -d ' ' -f -2 | tr -d ' ' | sort -u > arp_discovery_scan.txt
```


## Layer 3 Network Discovery Scans (ICMP ping scan)

```
nmap -n -sn --send-ip
```
> Layer 3 Network Discovery Scan Output to a File

```
nmap -n -sn --send-ip target_host -oG - | grep -o '^[^#]*' | cut -d ':' -f 2 | cut -d ' ' -f -2 | tr -d ' ' sort -u > icmp_discovery_scan.txt
```


## Layer 4 Network Discovery Scans (UDP,TCP Syn, TCP ACK port scan)

> UDP Layer 4 Network Discovery Scan

```
nmap -n -Pn --host-timeout 2 -PU53,514
```

> TCP Syn Layer 4 Network Discovery Scan

```
nmap -n -Pn --host-timeout 2 -PS21-1023,3389,5985
```

> ACK Layer 4 Network Discovery Scan

```
nmap -n -Pn --host-timeout 2 -PA21-1023,3389,5985
```

> UDP Layer 4 Network Discovery Scan Output to a File

```
 nmap -n -Pn --host-timeout 2 -PU53,514 target_host  -oG - | grep -o '^[^#]*' | cut -d ':' -f 2 | cut -d ' ' -f -2 | tr -d ' ' | sort -u  > udp_discovery_scan.txt
```

> TCP Syn Layer 4 Network Discovery Scan Output to a File

```
nmap -n -Pn --host-timeout 2 -PS21-1023,3389,5985 target_host -oG - | grep -o '^[^#]*' | cut -d ':' -f 2 | cut -d ' ' -f -2 | tr -d ' ' | sort -u  > tcpack_discovery_scan.txt
```

> ACK Layer 4 Network Discovery Scan Output to a File

```
nmap -n -Pn --host-timeout 2 -PS21-1023,3389,5985 target_host  -oG - | grep -o '^[^#]*' | cut -d ':' -f 2 | cut -d ' ' -f -2 | tr -d ' ' | sort -u  > tcpsyn_discovery_scan.txt
```

### Get Geoip Info With Script 

> Script traceroute-geolocation uses website [http://www.geoplugin.com/](http://www.geoplugin.com/)

```
nmap --traceroute --script traceroute-geolocation target_host
```

> Geoip script with output in kml file format

```
nmap --traceroute --script traceroute-geolocation --script-args traceroute-geolocation.kmlfile=traceroute_map.kml target_host
```

> View kml file at [https://www.gpsvisualizer.com/]( https://www.gpsvisualizer.com/)


### Whois Lookup With Script
```
nmap -sn --script whois-* target_host
```

> Disable thrid party whois db

```
nmap --script whois-ip --script-args whois.whodb=nofollow
```

> Disable cache

```
nmap -sn --script whois-ip --script-args whois.whodb=nocache
```

### Shodan Lookup 

> Shodan is a powerful search engine for external network exploration
> Get the api key from [https://developer.shodan.io/](https://developer.shodan.io/)

```
nmap -sn -Pn -n --script shodan-api --script-args shodan-api.apikey=shodan_api_key target_host
```

> Output Shodan search to a cvs file

```
 nmap -sn -Pn -n --script shodan-api --script-args shodan-api.apikey='shodan_api_key',shodan-api.outfile=shodan_results.csv
```

### Google Safe Browsing Check 

> Google safe Browsing check is a service to idenify unsafe websites
> This script checks if hosts are on Google's blacklist suspected malware and phishing servers
> Get the api key from [https://developers.google.com/safe-browsing/?csw=1](https://developers.google.com/safe-browsing?csw=1)

```
 nmap -p 80 --script http-google-malware --script-args http-google-malware.api=google_api_key target_host
```

### Enumerate Website For Email, Usernames, etc 
```
 nmap -p 80,443 --script http-grep target_host
```

> Use match args for custom grep matches

```
nmap -p 80 <target> --script http-grep --script-args='match=""'
```

### Find Host That Are Running Web Servers
```
 nmap -p 80,443 -sV -oG – target_host | grep open
```
### Find Hostnames That Point To An IP/Another Hostname
```
 nmap -sn --script hostmap-* target_host
 ```
### Brute Force Subdomain Records 
```
nmap --script dns-brute target_host
```

> Add your own customer wordlist

```
nmap --script dns-brute --script-args dns-brute.hostlist=wordslist.txt target_host
```

> Change the threads being used

```
 nmap --script dns-brute --script-args dns-brute.threads=num target_host
```

### Google's People API To Query Gmail Info 
> Need a valid gmail account to query gmail accounts
> THIS USES AN EXTERNAL SCRIPT at [https://raw.githubusercontent.com/cldrn/nmap-nse-scripts/master/scripts/google-people-enum.nse](https://raw.githubusercontent.com/cldrn/nmap-nse-scripts/master/scripts/google-people-enum.nse)


```
 nmap -sn --script google-people-enum --script-args='username=your_username,password=your_password,userdb=target_users.txt' target_domain
```

### Vulners To Query Services For Vulnerablities 
> Uses [vulners](https://vulners.com/api/v3/burp/software/), vulnerablity DB aggregate, to find vulnerable services basic on the enumeration info the -sV flag gives it
> The more aggressive the service scan, the bettter the results

```
nmap -sV --script vulners target_host
```

> Set a min cvss score to report

```
nmap -sV --script vulners --script-args mincvss=0-10 target_host
```
### Vulscan To Query Services For Vulnerablities DB MITRE CVE, Exploit-Db, scip VulDB 
> THIS USES AN EXTERNAL SCRIPT at [https://github.com/cldrn/nmap-nse-scripts/blob/master/scripts/vulscan.nse](https://github.com/cldrn/nmap-nse-scripts/blob/master/scripts/vulscan.nse])
> Compared to the Vulners scan this scan give less reliable results but can be preformed without needing to contact external servers if the DB is downloaded before hand

> Download the DB

```
 nmap -sV --script vulscan --script-args vulscan.updatedb LOCALHOST 
```

> Run the vulnerablity scan agenist a target

```
 nmap -sV --script vulscan target_host
```
### Find DCs
> Find the AD LDAP

```
nmap -sS -sV -p 389 target_host
```

> Find master netbios

```
nmap -sn --script broadcast-netbios-master-browser
```

> Find the DNS on the network

```
 nmap -R -sn --packet-trace -Pn google.com
```

#### List supported HTTP methods
```
 nmap -p 80,443 --script http-methods --script-args httpmethods.test-all=true target_host
``` 
#### List available paths and folders
```
 nmap --script http-enum -sV target_host
``` 
#### Scanning web servers for XSS vulnerabilities
```
 nmap -sV --script http-unsafe-output-escaping target_host
``` 
#### Scanning web servers for SQL injection
```
 nmap -sV --script http-sql-injection target_host
``` 
#### Scanning web servers for XST vulnerabilities 
```
 nmap -sV --script http-methods,http-trace --script-args http-methods.retest target_host
``` 
#### Find WAF
```
 nmap -sV --script http-waf-detect,http-waf-fingerprint target_host
```
#### Brute-forcing HTTP basic auth
```
 nmap -p 80 --script http-brute target_host
```
#### Wordpress bruteforce common password
```
 nmap -sV --script http-wordpress-brute target_host
```
#### Finding web servers for default creds
```
 nmap -sV --script http-default-accounts target_host
``` 
#### Finding expossed Git repos
```
 nmap -sV --script http-git target_host
 ```
#### Brute force SMTP
```
 nmap -p 25 --script smtp-brute target_host
 ```
#### Brute force IMAP
```
 nmap -p 143 --script imap-brute target_host
 ```
#### Brute force POP3
```
 nmap -p 110 --script pop3-brute target_host
``` 
#### Enumerate users
```
 nmap -p 25 --script-smtp-enum-users target_host
 ```
#### SMTP running on alternate ports
```
 nmap -sV --script strangeport target_host
 ```
#### Discovering open relays
```
 nmap -sV --script smtp-open-relay -v target_host
``` 
#### Get available SMTP commands
```
 nmap -p 25 --script=smtp-commands target_host
``` 
#### SSH enumerate algorithms
```
 nmap -p 22 --script=ssh2-enum-algos target_host
``` 
#### SSH enumerate hostkeys
```
 nmap -p 22 --script=ssh-hostkey target_host
``` 
#### SSH enumerate with public keys 
```
 nmap -p 22 --script ssh-publickey-acceptance --script-args 'ssh.usernames={"root", "user"}, publickeys={"./id_your_rsa.pub", "./id_your_ed25519.pub"}' target_host
```
#### SSH brute force 

> Default password list is used if none are supplied

```
 nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst,ssh-brute.timeout=4s target_host
```
#### SSL get cert
```
 nmap -p 443 --script=ssl-cert target_host
``` 
#### SSL run all ssl scripts
```
 nmap -p 443 --script=ssl-* target_host
```
#### SSL heatbleed
```
 nmap -p 443 --script ssl-heartbleed target_host
``` 
#### Get MS SQL info
```
 nmap -sS -p 1433 --script ms-sql-info target_host
```

> Change the default MS SQL port

```
 nmap -sS -p 1433 --script ms-sql-info --script-args mssql.instance-port=1433 target_host
``` 
#### Brute force MS SQL passwords

```
 nmap -sT -p 1433 --script ms-sql-brute --script-args mssql.instance-all,userdb=customuser.txt,passdb=custompass.txt target_host
```

```
 nmap -sT -p 1433 --script ms-sql-brute --script-args userdb=customuser.txt,passdb=custompass.txt target_host
``` 
#### Dump MS SQL password hashes 
> Check for creds with ms-sql-empty-password

```
 nmap -sT -p 1433 --script ms-sql-empty-password,ms-sql-dump-hashes target_host
``` 
#### MySQL list databases 
> Default port 3306
> If no username and password is supplied then will try to brute force

```
 nmap -sT -p 3306 --script mysql-databases target_host
```

```
 nmap -sT -p 3306 --script mysql-databases --script-args mysqluser=mysql_username,mysqlpass=mysql_pass target_host
```
#### Brute force MySQL password
> Only uses nmap default password list

```
 nmap -sT -p 3306 --script mysql-brute  target_host
``` 
#### MySQL enumerate with empty password for default
```
 nmap -sT -p 3306 --script mysql-empty-password target_host
``` 
#### Oracle stealth brute force
```
 nmap -sT --script oracle-brute-stealth -p 1521 --script-args oracle-brute-stealth.sid=ORCL target_host
``` 
#### Get MongoDB info
```
 nmap -sS -p 27017 --script mongodb-info target_host
``` 
#### Get Cassandra info
```
 nmap -sS -p 9160 --script cassandra-info target_host
 ```
#### Find standard open ports for ICS/SCADA systems
```
 nmap -Pn -sT --scan-delay 1s --max-parallelism 1 -p 80,102,443,502,1089,1091,2222,4000,4840,20000,34962,34964,34980,44818,47808,55000,55003 target_host
```
#### Find control system ports (BACnet/IP)
```
 nmap -Pn -sU -p 47808 --script bacnet-info target_host
``` 
#### Find control system ports (ethernet/IP)
```
 nmap -Pn -sU -p 44818 --script enip-info target_host
``` 
#### Find SCADA Modbus device
```
 nmap -Pn -sT -p 502 --script modbus-discover --script-args aggressive=true target_host
``` 
#### Find SCADA Niagara Fox device
```
 nmap -Pn -sT -p 1911,4911 --script fox-info target_host
``` 
#### Find SCADA PCWorx device
```
 nmap -Pn -sT -p 1962 --script pcworx-info target_host
```
#### SMB vulns scan
> Use all nmap SMB vulnerability scripts

```
 nmap -sS -p 139,445 -script smb-vuln* --script-args=unsafe=1 target_host
```
#### SMB MS08-067
> Use metasploit for unpatched systems and ECLIPSEDWING for patched systems

```
 nmap -sS -p 139,445 --script smb-vuln-ms08-067 target_host
```
#### SMB getting windows information 
> Only works with SMBv1

```
 nmap -sS -p 139,445 --script smb-os-discovery target_host
```
#### SMB finding windows client with SMB signing disable
```
 nmap -sU -sS -p U:137,T:139,T:445 --script smb-security-mode target_host
```
#### SMB check if UDP is being used (bypass filtering)
```
 nmap -sU -p 137 --script smb-security-mode target_host
```
#### IIS showing windows 8.3 file naming scheme info
```
 nmap -p 80 --script http-iis-short-name-brute target_host
```
#### NetBIOS info
```
 nmap -v -sU -p 137 --script nbstat target_host
```
#### SMB enumeration 
> Old Windows 2000 servers allow without login

> SAMR enumeration and LSA bruteforcing

```
nmap -v -sU -sS -p U:137,T:139,T:445 --script smb-enum-users target_host
```

> Use lSA Only\
> More accounts info is return like system accounts, user accounts, groups, and aliases\
> LSA uses at least 10 packets while SAMR uses half\
> The LSA enumeration will create many Windows event log


```
nmap -v -sU -sS -p U:137,T:139,T:445 --script smb-enum-users --script-args lsaonly=true
target_host
```

> Use SAMR Only\
> Only user accounts are returned but only requires one packet for each user account making less noise on a network 

```
nmap -v -sU -sS -p U:137,T:139,T:445 --script smb-enum-users --script-args samronly=true target_host
```

#### Share folders enumeration
> Need username and password with permission

```
nmap -sS -sU -p U:137,T:139,T:445 --script smb-enum-shares --script-args smbusername=Administrator,smbpassword=Password target_host
```
#### Send wake on lan (wol) packet
```
nmap --script broadcast-wake-on-lan --script-args broadcast-wake-on-lan.MAC='00:00:00:00:00:00'
```
