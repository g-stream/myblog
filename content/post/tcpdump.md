+++
title = "tcpdump 抓包"
description = ""
tags = [
    "network"]
date = "2018-05-05"
categories = [
    "Development",
    "tcpdump",
]
menu = "main"
+++
# tcpdump 抓包

    tcpdump port 80 -w capture_file.pcap -i eth0 #经过eth0网卡的80口的包并写入capture_file.pcap

## 依据网卡、端口、ip、网络、协议类型过滤

    tcpdump -i eth0
    tcpdump host 1.1.1.1     #host指定包从ip传出或传入，下面两个则指明包的来源与目的地址
    tcpdump src 1.1.1.1
    tcpdump dst 1.0.0.1
    tcpdump net 1.2.3.0/24   #指定网络
    tcpdump port 3389        #指定端口
    tcpdump portrange 21-23  #端口范围
    tcpdump src port 1025    #指定来源端口
    tcpdump icmp             #指定包的协议类型为icmp
    tcpdump ip6              #指定ipv6包
    tcpdump less 32          #依据大小过滤
    tcpdump greater 64
    tcpdump <= 128 

## Advanced

一些高级选项：

    -X : Show the packet’s contents in both hex and ASCII.
    -XX : Same as -X, but also shows the ethernet header.
    -D : Show the list of available interfaces
    -l : Line-readable output (for viewing as you save, or sending to other commands)
    -q : Be less verbose (more quiet) with your output.
    -t : Give human-readable timestamp output.
    -tttt : Give maximally human-readable timestamp output.
    -i eth0 : Listen on the eth0 interface.
    -vv : Verbose output (more v’s gives more output).
    -c : Only get x number of packets and then stop.
    -s : Define the snaplength (size) of the capture in bytes. Use -s0 to get everything, unless you are intentionally capturing less.
    -S : Print absolute sequence numbers.
    -e : Get the ethernet header as well.
    -q : Show less protocol information.
    -E : Decrypt IPSEC traffic by providing an encryption key.
    -nn : Don’t resolve hostnames or port names.
    -c [num]: package number

过滤条件可以用以下命令组合：

    - AND
    and or &&
    - OR
    or or ||
    - EXCEPT
    not or !

Raw Output View

Use this combination to see verbose output, with no resolution of hostnames or port numbers, using absolute sequence numbers, and showing human-readable timestamps.

    tcpdump -ttnnvvS

Here are some examples of combined commands.
From specific IP and destined for a specific Port

Let’s find all traffic from 10.5.2.3 going to any host on port 3389.

    tcpdump -nnvvS src 10.5.2.3 and dst port 3389


Let’s look for all traffic coming from 192.168.x.x and going to the 10.x or 172.16.x.x networks, and we’re showing hex output with no hostname resolution and one level of extra verbosity.

    tcpdump -nvX src net 192.168.0.0/16 and dst net 10.0.0.0/8 or 172.16.0.0/16

## Non ICMP Traffic Going to a Specific IP

This will show us all traffic going to 192.168.0.2 that is not ICMP.

    tcpdump dst 192.168.0.2 and src net and not icmp
## Traffic From a Host That Isn’t on a Specific Port

This will show us all traffic from a host that isn’t SSH traffic (assuming default port usage).

    tcpdump -vv src mars and not dst port 22

As you can see, you can build queries to find just about anything you need. The key is to first figure out precisely what you’re looking for and then to build the syntax to isolate that specific type of traffic.

Keep in mind that when you’re building complex queries you might have to group your options using single quotes. Single quotes are used in order to tell tcpdump to ignore certain special characters—in this case below the “( )” brackets. This same technique can be used to group using other expressions such as host, port, net, etc.

    tcpdump 'src 10.0.2.4 and (dst port 3389 or 22)'
## Isolate TCP Flags

You can also use filters to isolate packets with specific TCP flags set.
Isolate TCP RST flags.

The filters below find these various packets because tcp[13] looks at offset 13 in the TCP header, the number represents the location within the byte, and the !=0 means that the flag in question is set to 1, i.e. it’s on.

    tcpdump 'tcp[13] & 4!=0'
    tcpdump 'tcp[tcpflags] == tcp-rst'
## Isolate TCP SYN flags.

    tcpdump 'tcp[13] & 2!=0'
    tcpdump 'tcp[tcpflags] == tcp-syn'
## Isolate packets that have both the SYN and ACK flags set.

    tcpdump 'tcp[13]=18'

Only the PSH, RST, SYN, and FIN flags are displayed in tcpdump‘s flag field output. URGs and ACKs are displayed, but they are shown elsewhere in the output rather than in the flags field.
## Isolate TCP URG flags.

    tcpdump 'tcp[13] & 32!=0'
    tcpdump 'tcp[tcpflags] == tcp-urg'
## Isolate TCP ACK flags.

    tcpdump 'tcp[13] & 16!=0'
    tcpdump 'tcp[tcpflags] == tcp-ack'
## Isolate TCP PSH flags.

    tcpdump 'tcp[13] & 8!=0'
    tcpdump 'tcp[tcpflags] == tcp-psh'
## Isolate TCP FIN flags.

    tcpdump 'tcp[13] & 1!=0'
    tcpdump 'tcp[tcpflags] == tcp-fin'

## Everyday Recipe Examples

Because tcpdump can output content in ASCII, you can use it to search for cleartext content using other command-line tools like grep.

Finally, now that we the theory out of the way, here are a number of quick recipes you can use for catching various kinds of traffic.
## Both SYN and RST Set

    tcpdump 'tcp[13] = 6'
## Find HTTP User Agents

The -l switch lets you see the traffic as you’re capturing it, and helps when sending to commands like grep.

    tcpdump -vvAls0 | grep 'User-Agent:'
## Cleartext GET Requests

    tcpdump -vvAls0 | grep 'GET'
## Find HTTP Host Headers

    tcpdump -vvAls0 | grep 'Host:'
## Find HTTP Cookies

    tcpdump -vvAls0 | grep 'Set-Cookie|Host:|Cookie:'
## Find SSH Connections

This one works regardless of what port the connection comes in on, because it’s getting the banner response.

    tcpdump 'tcp[(tcp[12]>>2):4] = 0x5353482D'
## Find DNS Traffic

    tcpdump -vvAs0 port 53
## Find FTP Traffic

    tcpdump -vvAs0 port ftp or ftp-data
## Find NTP Traffic

    tcpdump -vvAs0 port 123
## Find Cleartext Passwords

    tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -lA | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd= |password=|pass:|user:|username:|password:|login:|pass |user '
## Find Traffic With Evil Bit

There’s a bit in the IP header that never gets set by legitimate applications, which we call the “Evil Bit”. Here’s a fun filter to find packets where it’s been toggled.

    tcpdump 'ip[6] & 128 != 0'