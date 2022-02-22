# RedLion tools

I've done some work looking into RedLion ICS HMI devices. They are beically touchscreen computers with networking capabilities.

I discovered how to fingerprint the devices using their control protocol running on port 789. These fingerprints ended up being used by Shodan. I don't have anything to do with Shodan, but they used these fingerprints to add to their product. [Red Lion on Shodan](https://www.shodan.io/search?query=port%3A789+product%3A%22Red+Lion+Controls%22) (requires Shodan login).

I had put these on a different repository but have moved them over to my main github account.


Crimson v3 NMAP Script Repository
=================================

This is a repository for nmap NSE scripts related to the ICS HMI touchpanels
made by Red Lion Controls (http://redlion.net). These devices support updates
over TCP port 789. 

Scripts
-------

+ cr3-fingerprint.nse : Hosts with TCP:789 open will be fingerprinted

```
Nmap scan report for redlion.example.com (127.0.0.1)
Host is up (0.14s latency).
Not shown: 1021 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
502/tcp open  asa-appl-proto
789/tcp open  unknown
| cr3-fingerprint: 
| Manufacturer: Red Lion Controls
|_Model: G310C2
```

Crimson v3 Wireshark Protocol Dissector
=======================================

This is a repository for a Wireshark dissector for the Crimson v3 protocol
related to the ICS HMI touchpanels made by Red Lion Controls (http://redlion.net). 
These devices support updates over TCP port 789. This minimal dissector is a
starting point for understanding this protocol.


