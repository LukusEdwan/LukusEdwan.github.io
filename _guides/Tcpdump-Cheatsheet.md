---
layout: default
tags: tcpdump packetcapture cheatsheet
---

# Tcpdump Cheatsheet

> Help page
> -h

```
tcpdump -h
```

> Manual page

```
man tcpdump
```

## Tcpdump Flags
See all the flags with the manual pages. This is a list of the most uses

> Select an interface\
> Use the Any interface to capture from all\
> -i any | lo | tun0 | etc

```
tcpdump -i any
```

> Print the payload in ASCII\
> Useful with http/https requests and responses\
> -A 

```
tcpdump -A -i any
```

> Only capture specified number of packets\
> -c/--count

```
tcpdump -c num -i any
```

> List all available interfaces\
> -D

```
tcpdump -D
```

> List link local protocols on the device\
> -L

```
tcpdump -L
```

> Print the link-level header on each dump line\
> -e

```
tcpdump -e -i any
```

> Put the IEEE 802.11 Wi-Fi interface in monitor mode\
> -I/--monitor-mode

```
tcpdump -I -i any
```

> Use a filter file to filter the packet capture\
> -F

```
tcpdump -F filter_file.txt -i any
```

> Read a pcap file\
> -r

```
tcpdump -r file.pcap
```

> Write to a pcap file\
> -w

```
tcpdump -w file.pcap -i any
```

> Rotate the write to pcap file base on the seconds specified\
> Output files will have file name specified with `-w` switch with contactination of the `strftime` format\
> -G secs

> Note: This command will fail if not in writable dir. The safest dir is /tmp but tmp will have all files purged on powercycle

> Example: Timezone (%Z) _ Year-Month-Day (%F) _ Hours:Minutes:Seconds (%T)

```
tcpdump -G num -w %X_%F_%T.pcap -i any
```

> Do not verify checksum for IP, TCP, and UDP\
> -K\ --dont-verify-checksums

```
tcpdump -K -i any
```

> Do not convert ip addresses to names\
> -n

```
tcpdump -n -i any
```

> No promiscuous mode\
> Only capture packets coming from and to the local host\
> -p

## Capture Filters
The BPF filter in tcpdump can be used to filter the output\
Add to the end of the tcpdump command to a apply filters
---
Example: Filter for UDP traffic on port 53 from source mac address to host 172.16.0.1 or network 10.0.0.0/16

```
tcpdump -i any udp dst port 53 && ether src cc:23:f3:00:23:12:01 and dst host 172.16.0.1 or net 10.0.0.0/16
```

| Description                                  | Primitves 
|:---------------------------------------------|:---------------------------------------
| Match host IP source or destination          | [src\dst] host xx.xx.xx.xx
| Match host Ethernet source or destination    | ether [src\dst] host xx:xx:xx:xx:xx:xx
| Match when host is a gateway                 | gateway host xx.xx.xx.xx
| Match packets to/from a network              | [src\dst] net xx.xx.xx.xx/xx
| Match TCP or UDP packet sent to a port       | [tcp\udp] [src\dst] port xx
| Match TCP or UDP packet sent to port range   | [tcp\udp] [src\dst] portrange xx-xx
| Match packets less than or equal to length   | less num
| Match packets greater than or equal to length| greater num
| Match ethernet, ipv4, or ipv6 protocol       | ether\ip\ip6 proto protocol_name
| Match ethernet or ipv4 broadcast             | ether\ip broadcast
| Match ethernet, ipv4, or ipv6 multicast      | ether\ip\ip6 multicast
| Match 802.11 frames based on type or sub type| type mgt\ctl\data [subtype type_name]
| Match 802.1Q frames with option of vlan ID   | vlan [vlan_ID]
| Match MPLS packets with option of label      | mpls [label_name]

---

| Protocols        | Modifiers     | TCP Flags     | ICMP Types
|:-----------------|:--------------|:--------------|:----------------
| arp              | ! or `not`    | tcp-urg       | icmp-echoreply
| ether            | && or `and`   | tcp-ack       | icmp-unreach
| fddi             | \|\| or `or`  | tcp-psh       | icmp-sourcequench
| icmp             |               | tcp-rst       | icmp-redirect
| ip               |               | tcp-syn       | icmp-echo
| ip6              |               | tcp-fin       | icmp-routeradvert
| link             |               |               | icmp-routersolicit
| ppp              |               |               | icmp-timxceed
| radio            |               |               | icmp-paramprob
| rarp             |               |               | icmp-tstamp
| slip             |               |               | icmp-tstampreply
| tcp              |               |               | icmp-ireq
| udp              |               |               | icmp-ireqreply
| tr               |               |               | icmp-maskreply
| wlan             |               |               | icmp-maskreq
