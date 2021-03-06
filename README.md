# spoof

A simple PoC for generating spoofed IPv4 packets. In particular, the 
intent is to:

- Spoof the IPv4 source address within the IP header
- Optionally modify IP and/or TCP fields (only recommended to manipulate 
source address within IP header and TCP flags within TCP header unless 
you know what your doing)

## Purpose:

Demonstrate a PoC for dealing with raw sockets. The driver for this was to 
provide an interface for spoofing a source IPv4 address or hostname.

This is a proof of concept and is not intended to:
- Be free of bugs
- Be used maliciously
- Target any asset without prior authorization
- Be modified with any intent outside of personal research or learning

** See the license that should accompany this README and code.

## Note:

To get deeper than the typical app layer, we need to deal with raw sockets. 
This requires elevated privileges since you could do evil things. 

The source argument passed will be inputted into the source address 
field of the IP header. The destination address will be inputted 
into the destination field of the IP header. The destination port 
will be placed into the destination port field of the TCP header.
The intent would be to use a source address that is NOT the real 
source address or hostname, thereby creating a "spoof" scenario.

On BSD systems (OSX and FREEBSD), spoofing 127.0.0.1 causes sendto(2) to 
fail with: "Can't assign requested address". Use "localhost" or another 
IPv4 address or hostname.

If compiled via Cygwin on Windows:
- Ensure you launch your terminal as "Administrator"
- Header tcp.h (v8.1) does not support CWR or ECE :(
    
## Compile:

gcc -D \<TARGET-OS\> -o spoof spoof.c

Where \<TARGET-OS\> is one of: LINUX, FREEBSD, OSX, or CYGWIN (depending on the 
platform you are compiling on).

## Usage:

```
spoof [options] <arguments>
spoof <arguments> [options]

[Options]
-f <tcpflag> # One or more TCP flags to enable. If using
             # more than one flag, each should be appended
             # together (e.g. ASRF). The available flags are:
             # A or a (enables the ACK bit)
             # C or c (enables the CWR bit)
             # E or e (enables the ECE bit)
             # F or f (enables the FIN bit)
             # P or p (enables the PSH bit)
             # R or r (enables the RST bit)
             # S or s (enables the SYN bit)
             # U or u (enables the URG bit)
-m <message> # Optional message to send in the packet

[Arguments]
-s <src>    # Source IPv4 address or hostname to spoof
-d <dst>    # Destination IPv4 address or hostname of victim
-p <dport>  # Destination port to send spoofed TCP packet
```

# Execute:

<pre>
Example 1:
        
$ sudo ./spoof -s 123.45.67.8 -d 192.168.0.10 -p 55555

The above will not set any TCP flags, spoof the source address 
"123.45.67.8", and send a packet to the destination "192.168.0.10" 
over TCP port of 55555.

Example 2:

$ sudo ./spoof -f FPU -d my.victim.com -p 1337 -s foobar.com 

The above will set the FIN/PSH/URG bits (AKA X-mas tree attack), spoof 
the source address "foobar.com", and send a packet to the destination 
"my.victim.com" over TCP port of 1337.

Example 3:

$ sudo ./spoof -f PA -d my.victim.com -p 1337 -s l84dinner.com -m "Sp00fing 4 lulz"

The above will set the PSH/ACK bits, spoof the source address "l84dinner.com", 
send a packet containing a data payload of "Sp00fing 4 lulz" to the destination 
"my.victim.com" over TCP port of 1337.
