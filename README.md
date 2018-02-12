# spoof

A simple PoC for generating spoofed IPv4 packets. In particular, the 
intent is to:

- Spoof the IPv4 source address within the IP header
- Optionally modify IP and/or TCP fields (only recommended to manipulate 
source address within IP header and TCP flags within TCP header unless 
you know what your doing)

Purpose:
========

Demonstrate a PoC for dealing with raw sockets. The driver for this was to 
provide an interface for spoofing a source IPv4 address.

This is a proof of concept and is not intended to:
- Be free of bugs
- Be used maliciously
- Target any asset without prior authorization
- Be modified with any intent outside of personal research or learning

** Also, see the license that should accompany this README and code.

Note:
=====

To get deeper than the typical app layer, we need to deal with raw sockets. 
This requires elevated privileges since you could do evil things. 

The source argument passed will be inputted into the source address field 
of the IP header. 

If you feel like modifying TCP flags, see the definition constants in spoof.c 
(prefixed with "TCP_FLAG_"). They can be enabled (1) or disabled (0) as needed. 
This will of course require a recompile upon each change as I have not provided
an interface via arguments (yet). IMPORTANT: It is recommended to avoid modifying 
any values outside of TCP flags unless you know what you are doing.

On BSD systems (OSX and FREEBSD), spoofing 127.0.0.1 causes sendto(2) to 
fail with: "Can't assign requested address". Use "localhost" or another 
IPv4 address. The former will use the broadcast address as the source.

Compile:
========

gcc -D \<TARGET-OS\> -o spoof spoof.c

Where \<TARGET-OS\> is one of: LINUX, FREEBSD, or OSX (depending on the platform you are compiling on).

Usage:
======

spoof \<src\> \<dst\> \<dport\>

Execute:
========

$ sudo ./spoof 123.45.67.8 192.168.0.10 55555

The above will spoof the source address "123.45.67.8" and send a packet 
to the destination "192.168.0.10" over TCP port 55555.
