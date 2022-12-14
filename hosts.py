#!/bin/env python3
# A simple hosts file manager intended to be ran via sudo

import sys

# Specify the start and end markers in the hosts file
start_marker = "### BEGIN HOSTS MANAGED ENTRIES ###\n"
end_marker = "### END HOSTS MANAGED ENTRIES ###\n"

# Hosts file location
hosts_file_path = "/etc/hosts"

def usage():
    print("""Usage:
{0} <command> [parameters]

Commands:
add <ip> <hostname> - Add an IP and corrosponding hostname to the hosts file
del <ip | hostname> - Deletes the specified IP or hostname from the hosts file
clear               - Clears out all ips/hostnames that were added by this utility

Examples:
{0} add 10.10.10.10 myhost.local
{0} del 10.10.10.10
{0} del myhost.local
{0} clear
""".format(sys.argv[0]))
    exit()

def findMarkers():
    # Check the hosts file for our markers. If found return the 
    # line numbers of the start and end. 0, 0 if not found
    # and attempt to add them.
    start = 0
    end = 0

    try:
        file = open(hosts_file_path, "r")
        i = 0
        for line in file:
            if(line == start_marker):
                start = i
            if(line == end_marker):
                end = i
            i += 1
        if(start == end):
            print("No hosts file markers found, setting up hosts file.")
            setupHostsFile()
            start, end = findMarkers()
            if(start == end):
                print("Error: Unable to add markers to hosts file.")
                exit()
    except:
        print("Error opening hosts file and adding markers.")
        exit()
    return start, end

def setupHostsFile():
    # Adds the markers to the hosts file
    # TODO: Confirm the file exists, and that the markers are added
    try:
        file = open(hosts_file_path, "a")
        file.write(start_marker)
        file.write(end_marker)
        file.close()
    except:
        print("Error opening hosts file for writing.")
        exit()

def validateIp(ip):
    # Validate that an IP is a valid ipv4 or ipv6 address
    # Use regex
    return True

def validateHostname(hostname):
    # Validate the hostname with dns rfc
    return True

if(len(sys.argv) == 1 or len(sys.argv) > 4):
    usage()
else:
    # TODO: Confirm hosts file path is valid and exists, otherwise error out. 
    try:
        f = open(hosts_file_path, "r")
    except:
        print("Error: Hosts file '{0}' was not found!\nPlease confirm file path and update in script if needed.".format(hosts_file_path))
        exit()

    mode = sys.argv[1]

    if(mode == "add"):
        if(len(sys.argv) != 4):
            print("Error: Not enough arguments! Please supply IP and HOSTNAME")
            usage()
        else:
            ip = sys.argv[2]
            hostname = sys.argv[3]
            # TODO: Sanatize and confirm ip and hostname formats are valid
            if validateIp(ip) and validateHostname(hostname):
                new_hosts_entry = "{0}\t{1}\n".format(ip, hostname)
            else:
                print("IP or hostname are invalid! Please check and try again.")
                exit()

            # Add an entry to the hosts file
            start, end = findMarkers()
                
            with open(hosts_file_path, 'r+') as file:
                contents = file.readlines()
                for index, line in enumerate(contents):
                    if start_marker in line:
                        contents.insert(index + 1, new_hosts_entry)
                        break
                file.seek(0)
                file.writelines(contents)
            print("Added '{0}' to hosts file.".format(new_hosts_entry.strip('\n')))

    if(mode == "del"):
        to_delete = sys.argv[2]
        deleted = False
        # Delete the specified line
        start, end = findMarkers()
        with open(hosts_file_path, 'r+') as file:
            contents = file.readlines()
            for index, line in enumerate(contents):
                if index > start and index < end:
                    if to_delete in line:
                        deleted = True
                        contents.remove(line)
            file.seek(0)
            file.writelines(contents)
            file.truncate()
        if deleted:
            print("Found entry to delete: {0}".format(line))
        else:
            print("No matching entries found for '{0}'".format(to_delete))

    if(mode == "clear"):
        # Clear out all managed lines
        start, end = findMarkers()
        lines = ""
        try:
            with open(hosts_file_path, 'r+') as file:
                contents = file.readlines()
                for index, line in enumerate(contents):
                    if index > start and index < end:
                        lines += line

                for line in lines.split("\n"):
                    if line != "":
                        print("Removing: {0}".format(line))
                        contents.remove(line + "\n")
                file.seek(0)
                file.writelines(contents)
                file.truncate()
        except:
            print("Error: Unable to open hosts file.")
            exit()
