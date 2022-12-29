# Hosts - Python hosts file manager
This is a Python script that adds and removes entries to your `hosts` file. It was created to assist in adding and removing these entries when doing CTF's which often require adding entries to your hosts file.

I was tired of manually adding entries and never cleaning them up, so I created `hosts.py` to help manage that for me. 

## Usage
```
hosts.py <command> [parameters]

Commands:
add <ip> <hostname> - Add an IP and corrosponding hostname to the hosts file
del <ip | hostname> - Deletes the specified IP or hostname from the hosts file
clear               - Clears out all ips/hostnames that were added by this utility

Examples:
hosts.py add 10.10.10.10 myhost.local
hosts.py del 10.10.10.10
hosts.py del myhost.local
hosts.py clear
```
