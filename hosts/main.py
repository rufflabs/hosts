#!/.venv/bin/python3
import os
import re
import argparse
import time
from functools import reduce
import subprocess

import validators as valid


class HostsFile:
    """
    This class is used to manage the hosts file.
    """
    START_MARKER = "### BEGIN HOSTS MANAGED ENTRIES ###\n"
    END_MARKER = "### END HOSTS MANAGED ENTRIES ###\n"

    HOST_FILE = "/etc/hosts"
    BACKUP_DIR = "~/.local/share/hosts"
    BACKUP_PATH = f"{BACKUP_DIR}/hosts-{{timestamp}}.bak"
    MAX_BACKUPS = 10

    def __init__(self, hosts_file_path: str = HOST_FILE):
        """
        Initialize the HostsFile object
        :param hosts_file_path: str
        """
        self.hosts_file_path = hosts_file_path

        if not self._check_if_markers_exist() and self._hosts_file_is_writable():
            self._setup_hosts_file()

        self.start_markers_index, self.end_markers_index = self._find_markers()

    @staticmethod
    def _ip_is_reachable(ip: str) -> str:
        """
        Check if the given ip is reachable
        :param ip: str (IPv4 or IPv6)
        :return: str
        """
        try:
            if valid.ipv6(ip):
                subprocess.check_output(["ping6", "-c", "1", "-W", "2", ip], stderr=subprocess.STDOUT)
            else:
                subprocess.check_output(["ping", "-c", "1", "-W", "2", ip], stderr=subprocess.STDOUT)
            return "ONLINE"
        except FileNotFoundError:
            return "UNKNOWN"
        except subprocess.CalledProcessError:
            return "OFFLINE"

    @staticmethod
    def _validate_ip(ip_local: str) -> bool:
        """
        Validate an IP address (IPv4 and IPv6)
        :param ip_local: str (IPv4 or IPv6)
        :return: bool
        """
        return valid.ipv4(ip_local) or valid.ipv6(ip_local)

    @staticmethod
    def _validate_hostname(hostname: str) -> bool:
        """
        Validate the given hostname
        :param hostname: str (e.g. example.com, raspi, ...)
        :return: bool
        """

        return valid.domain(hostname) or re.match(r"^(?!\d)[a-zA-Z0-9-]*[a-zA-Z][a-zA-Z0-9-]*$", hostname)

    def _index_in_section(self, index: int) -> bool:
        """
        Check if the given index is in the section
        :param index: int
        :return: bool
        """
        return self.start_markers_index < index < self.end_markers_index

    def _invalid_section(self) -> bool:
        """
        Check if the section is invalid
        :return: bool
        """
        return self.start_markers_index == -1 or self.end_markers_index == -1

    def _save_backup_of_hosts_file(self) -> None:
        """
        Save a backup of the hosts file
        :return: None
        """
        if not self._hosts_file_is_readable():
            raise FileNotFoundError(f"Hosts file not found or not readable at {self.hosts_file_path}.")

        if not os.path.exists(self.BACKUP_DIR):
            os.makedirs(self.BACKUP_DIR)

        backup_path = self.BACKUP_PATH.format(timestamp=int(time.time()))

        if not os.path.exists(backup_path):
            with open(backup_path, "w") as backup_file:
                backup_file.write("")

        backup_files = sorted([f for f in os.listdir(self.BACKUP_DIR) if f.startswith("hosts")], reverse=True)

        if len(backup_files) >= self.MAX_BACKUPS:
            for f in backup_files[self.MAX_BACKUPS:]:
                os.remove(f"{self.BACKUP_DIR}/{f}")

        with open(self.hosts_file_path, "r") as hosts_file:
            lines: list[str] = hosts_file.readlines()

        with open(backup_path, "w") as backup_file:
            for i, line in enumerate(lines):
                if self._index_in_section(i):
                    backup_file.write(line)

        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup of hosts file failed. Could not save the backup at {backup_path}.")

        print(f"INFO: Backup of hosts file saved at {backup_path}")

    def _hosts_file_is_readable(self) -> bool:
        """
        Check if the hosts file exists and is readable
        :return: bool
        """
        return os.path.exists(self.hosts_file_path) and os.access(self.hosts_file_path, os.R_OK)

    def _hosts_file_is_writable(self) -> bool:
        """
        Check if the hosts file exists and is writable
        :return: bool
        """
        return os.path.exists(self.hosts_file_path) and os.access(self.hosts_file_path, os.W_OK)

    def _hosts_file_is_valid(self) -> bool:
        """
        Check if the hosts file exists and is readable and writable
        :return: bool
        """
        return self._hosts_file_is_readable() and self._hosts_file_is_writable()

    def _check_if_markers_exist(self) -> bool:
        """
        Check if the markers exist in the hosts file
        :return: bool
        """
        if not self._hosts_file_is_readable():
            raise FileNotFoundError(f"Hosts file not found or not readable at {self.hosts_file_path}.")

        found_markers: list[bool] = [False, False]

        with open(self.hosts_file_path, "r") as hosts_file:
            for line in hosts_file:
                if line == self.START_MARKER:
                    found_markers[0] = True
                elif line == self.END_MARKER:
                    found_markers[1] = True

        if reduce(lambda a, b: a ^ b, found_markers):
            raise ValueError(
                f"Only one of the markers was found in the hosts file ('{self.hosts_file_path}'). Please resolve this "
                f"issue manually.")

        return all(found_markers)

    def _find_markers(self) -> tuple[int, int]:
        """
        Check the hosts file for our markers. If found return the line numbers of the start and end. -1, -1 if not found
        :return: tuple
        """
        start_local = -1
        end_local = -1

        if not self._hosts_file_is_readable():
            raise FileNotFoundError(f"Hosts file not found or not readable at {self.hosts_file_path}.")

        with open(self.hosts_file_path, "r") as hosts_file:
            for i, l in enumerate(hosts_file):
                if l == self.START_MARKER:
                    start_local = i
                elif l == self.END_MARKER:
                    end_local = i

        return start_local, end_local

    def _setup_hosts_file(self):
        """
        Adds the markers to the hosts file
        :return: None
        """
        if not self._hosts_file_is_valid():
            raise FileNotFoundError(f"Hosts file not found or not readable/writable at {self.hosts_file_path}.")

        with open(self.hosts_file_path, "a") as hosts_file:
            hosts_file.write(self.START_MARKER)
            hosts_file.write(self.END_MARKER)

        print(f"INFO: Added markers to hosts file at {self.hosts_file_path}.")

    def _get_line_of(self, identifier: str) -> int:
        """
        Get the line number of the given identifier
        :param identifier: str
        :return: int
        """
        if not self._hosts_file_is_readable():
            print(f"Hosts file not found or not readable at {self.hosts_file_path}.")
            return -1

        with open(self.hosts_file_path, "r") as hosts_file:
            for i, line in enumerate(map(self._get_ip_and_hostname_form_line, hosts_file.readlines())):
                if identifier in line:
                    return i

        return -1

    def _hostname_exists(self, hostname: str) -> bool:
        """
        Check if the given hostname exists in the hosts file
        :param hostname: str
        :return: bool
        """
        return self._get_line_of(hostname) != -1

    def _get_ip_and_hostname_form_line(self, line: str) -> tuple[str | None, str | None]:
        """
        Get the IP and hostname from a line in the hosts file
        :param line: str
        :return: tuple (ip, host)
        """
        try:
            ip, host = line.split()
        except ValueError:
            return None, None

        if not self._validate_ip(ip) or not self._validate_hostname(host):
            return None, None

        return ip, host

    def _get_ip_and_hostname_from_index(self, index: int) -> tuple[str | None, str | None]:
        """
        Get the IP and hostname from the given index
        :param index: int
        :return: tuple (ip, host)
        """
        if not self._hosts_file_is_readable():
            print(f"Hosts file not found or not readable at {self.hosts_file_path}.")
            return None, None

        with open(self.hosts_file_path, "r") as hosts_file:
            lines: list[str] = hosts_file.readlines()

        if index >= len(lines):
            return None, None

        return self._get_ip_and_hostname_form_line(lines[index])

    def _add_entry(self, _ip: str, hostname: str, print_note=True) -> bool:
        """
        Add an entry to the hosts file
        :param _ip: str (IPv4 or IPv6)
        :param hostname: str (e.g. example.com, raspi, ...)
        :param print_note: bool (default: True)
        :return: bool
        """
        if not self._hosts_file_is_valid():
            print(f"Hosts file not found or not readable nor writable at {self.hosts_file_path}.")
            return False

        if not self._validate_ip(_ip):
            print(f"Invalid IP address: {_ip}")
            return False

        if not self._validate_hostname(hostname):
            print(f"Invalid hostname: {hostname}")
            return False

        if self._get_line_of(hostname) != -1:
            print(f"Hostname '{hostname}' already exists in the hosts file at line {self._get_line_of(hostname)}.")
            return False

        if self._get_line_of(_ip) != -1:
            index: int = self._get_line_of(_ip)
            entry = self._get_ip_and_hostname_from_index(index)

            if print_note:
                print(f"NOTE: address '{_ip}' already exists in the hosts file at line {index}: '{entry[1]}'.")

        with open(self.hosts_file_path, "r") as hosts_file:
            lines: list[str] = hosts_file.readlines()

        with open(self.hosts_file_path, "w") as hosts_file:
            for i, line in enumerate(lines):
                hosts_file.write(line)
                if i == self.start_markers_index:
                    hosts_file.write(f"{_ip} {hostname}\n")

        self.start_markers_index, self.end_markers_index = self._find_markers()

        return True

    def _list_entries(self, in_only_section: bool = False, identifier: str = None) -> dict[int, tuple[str, str, bool]]:
        """
        List entries from the hosts file. If in_only_section is True, only entries between the markers are returned.
        :param in_only_section: bool (default: False)
        :return: list
        """
        if not self._hosts_file_is_readable():
            print(f"Hosts file not found or not readable at {self.hosts_file_path}.")
            return {}

        with open(self.hosts_file_path, "r") as hosts_file:
            lines: list[str] = hosts_file.readlines()

        entries: dict[int, tuple[str, str, bool]] = {}
        for i, (_ip, hostname) in enumerate(map(self._get_ip_and_hostname_form_line, lines)):
            if _ip and hostname:
                # if an identifier is given and the entry does not match the identifier
                if identifier and not any(re.compile(rf"{identifier}").search(e) for e in (_ip, hostname)):
                    continue

                if in_only_section:
                    if self._index_in_section(i):
                        entries[i] = (_ip, hostname, True)
                else:
                    entries[i] = (_ip, hostname, self._index_in_section(i))

        return entries

    def _eliminate_duplicates_in_section(self) -> None:
        """
        Eliminate duplicate entries in the hosts file
        :return: None
        """
        if not self._hosts_file_is_valid():
            raise FileNotFoundError(f"Hosts file not found or not readable nor writable at {self.hosts_file_path}.")

        with open(self.hosts_file_path, "r") as hosts_file:
            lines: list[str] = hosts_file.readlines()

        processed_entries: set[str] = set()
        duplicate_entries: list[int] = []

        with open(self.hosts_file_path, "w") as hosts_file:
            for i, (line, entry) in enumerate(zip(lines, map(self._get_ip_and_hostname_form_line, lines))):
                if self._index_in_section(i) and all(entry) and entry in processed_entries:
                    duplicate_entries.append(i)
                else:
                    if self._index_in_section(i) and all(entry):
                        processed_entries.add(entry)
                    hosts_file.write(line)

        if duplicate_entries:
            print(f"Deleted {len(duplicate_entries)} duplicate entries from the section (Line "
                  f"{', '.join(map(str, duplicate_entries))}).")

        self.start_markers_index, self.end_markers_index = self._find_markers()

    def add_entries(self, _ip: str, hostnames: list[str]) -> None:
        """
        Add all hostnames to the hosts file
        :param _ip: str (IPv4 or IPv6)
        :param hostnames: list[str] (e.g. example.com, raspi, ...)
        :return: None
        """
        self._save_backup_of_hosts_file()

        success: list[bool] = []

        for hostname in hostnames:
            success.append(self._add_entry(_ip, hostname, print_note=False))

        for hostname, s in zip(hostnames, success):
            if s:
                print(f"Added '{_ip}' and '{hostname}' to hosts file.")
            else:
                print(f"Failed to add '{_ip}' and '{hostname}' to hosts file.")

    def remove_entry(self, identifier: str) -> bool:
        """
        Remove an entry from the hosts file
        :param identifier: str (e.g. example.com, raspi, ...)
        :return: bool
        """
        self._save_backup_of_hosts_file()

        if not self._hosts_file_is_valid():
            print(f"Hosts file not found or not readable nor writable at {self.hosts_file_path}.")
            return False

        self.start_markers_index, self.end_markers_index = self._find_markers()

        if self._invalid_section():
            print("No entries from this script found in the hosts file.")
            return False

        with open(self.hosts_file_path, "r") as hosts_file:
            lines: list[str] = hosts_file.readlines()

        deleted_entries: list[int] = []

        with open(self.hosts_file_path, "w") as hosts_file:
            for i, (line, entry) in enumerate(zip(lines, map(self._get_ip_and_hostname_form_line, lines))):

                # if the line is outside the section or the identifier is not in the entry
                if not self._index_in_section(i) or \
                        (all(entry) and not any(re.compile(rf"{identifier}").search(e) for e in entry)):
                    hosts_file.write(line)
                else:
                    deleted_entries.append(i)

        if not deleted_entries:
            return False
        else:
            print(
                f"Deleted {len(deleted_entries)} entries from the section (Line {', '.join(map(str, deleted_entries))}).")

        self.start_markers_index, self.end_markers_index = self._find_markers()

        return True

    def clear_entries(self, with_backup: bool = True) -> bool:
        """
        Remove all entries between the markers
        :return: bool
        """
        if with_backup:
            self._save_backup_of_hosts_file()

        if not self._hosts_file_is_valid():
            print(f"Hosts file not found or not readable nor writable at {self.hosts_file_path}.")
            return False

        with open(self.hosts_file_path, "r") as hosts_file:
            lines: list[str] = hosts_file.readlines()

        with open(self.hosts_file_path, "w") as hosts_file:
            for i, line in enumerate(lines):
                if self._index_in_section(i):
                    continue
                hosts_file.write(line)

        self.start_markers_index, self.end_markers_index = -1, -1

        return True

    def update_entry(self, identifier: str, new_ip: str = None, new_hostname: str = None) -> None:
        """
        Update an entry in the hosts file
        :param identifier: str
        :param new_ip: str
        :param new_hostname: str
        :return: None
        """
        self._save_backup_of_hosts_file()

        if not self._hosts_file_is_valid():
            raise FileNotFoundError(f"Hosts file not found or not readable nor writable at {self.hosts_file_path}.")

        if not new_ip and not new_hostname:
            raise ValueError("At least one of the arguments 'new_ip' or 'new_hostname' must be given.")

        if new_ip and not self._validate_ip(new_ip):
            raise ValueError(f"Invalid IP address: {new_ip}")

        if new_hostname and not self._validate_hostname(new_hostname):
            raise ValueError(f"Invalid hostname: {new_hostname}")

        with open(self.hosts_file_path, "r") as hosts_file:
            lines: list[str] = hosts_file.readlines()

        lines: tuple[tuple[str, tuple[str | None, str | None]]] = tuple(zip(lines, map(
            self._get_ip_and_hostname_form_line, lines)))

        count_matched_hosts = len([line for line, entry in lines if entry[1] and re.compile(rf"{identifier}").search(entry[1])])
        count_matched_ips = len([line for line, entry in lines if entry[0] and re.compile(rf"{identifier}").search(entry[0])])

        if count_matched_hosts == 0 and count_matched_ips == 0:
            raise ValueError(f"No entries found matching '{identifier}'.")
        elif count_matched_hosts > 1 and new_hostname and not new_ip:
            raise ValueError(f"More than one entry found matching '{identifier}' and no new ip address given.")

        print(f"Found {count_matched_hosts} hostnames and {count_matched_ips} ip addresses matching '{identifier}'.")

        updated_entries: list[tuple[int, tuple[str, str]]] = []

        with open(self.hosts_file_path, "w") as hosts_file:
            for i, (line, entry) in enumerate(lines):
                if self._index_in_section(i) and all(entry) and \
                        any(re.compile(rf"{identifier}").search(e) for e in entry):
                    updated_entries.append((i, entry))

                    if new_ip:
                        entry = (new_ip, entry[1])
                    if new_hostname:
                        entry = (entry[0], new_hostname)

                    hosts_file.write(f"{entry[0]} {entry[1]}\n")
                else:
                    hosts_file.write(line)

        if updated_entries:
            print(
                f"Updated {f'ip {'addresses' if len(updated_entries) > 1 else 'address'} {', '.join(map(lambda e: f"'{e[1][0]}'", updated_entries))} to {new_ip}' if new_ip else ''}{f'{'hostnames' if len(updated_entries) > 1 else 'hostname'} {', '.join(map(lambda e: f"'{e[1][1]}'", updated_entries))} to \'{new_hostname}\'' if new_hostname else ''} for {len(updated_entries)} {'entries' if len(updated_entries) > 1 else 'entry'} in the section (Line {', '.join(map(lambda e: f"{e[0]}", updated_entries))}).")
        else:
            print(f"No matching entries found for '{identifier}' in the section managed by this script.")

        self._eliminate_duplicates_in_section()

    def list(self, identifier: str = None, in_only_section: bool = False,
             sort_by: str = "ip", ping: bool = False) -> bool:
        """
        List entries from the hosts file. If in_only_section is True, only entries between the markers are returned.
        :param identifier: str (default: None)
        :param in_only_section: bool (default: False)
        :param sort_by: str (default: "ip")
        :return: bool
        """
        entries = self._list_entries(in_only_section, identifier=identifier)

        if entries:
            if sort_by == "hostname":
                en = sorted(entries.items(), key=lambda x: x[1][1])
            else:
                en = sorted(entries.items(), key=lambda x: x[1][0])

            # ipv6: max 39 characters (8 groups of 4 hex digits + 7 colons)
            if in_only_section:
                print("Entries from the managed section:")

                if ping:
                    print(f"line {'status':<7} {'IP':<39} {'Hostname'}")
                    for index, (ip, host, s) in en:
                        print(f"{index:<4} {self._ip_is_reachable(ip):<7} {ip:-<39}-{host}")
                else:
                    print(f"line {'IP':<39} {'Hostname'}")
                    for index, (ip, host, s) in en:
                        print(f"{index:<4} {ip:-<39}-{host}")
            else:
                if ping:
                    print(f"  line {'status':<7} {'IP':<39} {'Hostname'}")
                    for index, (ip, host, s) in en:
                        print(f"{'*' if s else ' '} {index:<4} {self._ip_is_reachable(ip):<7} {ip:-<39}-{host}")
                else:
                    print(f"  line {'IP':<39} {'Hostname'}")
                    for index, (ip, host, s) in en:
                        print(f"{'*' if s else ' '} {index:<4} {ip:-<39}-{host}")

                print("Marked entries with '*' are from the managed section.")

            return True

        return False

    def backup(self, hostsfile: str = None, backup_dir: str = None, list_backups: int = None,
               restore: str = None, remove: str = None) -> None:
        """
        Backup the hosts file
        :param hostsfile: str (default: None)
        :param backup_dir: str (default: None)
        :param list_backups: int (default: None)
        :param restore: str (default: None)
        :param remove: str (default: None)
        :return: None
        """

        if list_backups:
            backup_files = sorted([f for f in os.listdir(backup_dir) if f.startswith("hosts")], reverse=True)

            print(f"Last {list_backups} backups:")
            print(f"Index {'Date':<21} {'Size kB':>13}   {'Filename'}")
            for i, f in enumerate(backup_files[:list_backups]):
                print(f"{i:>4}. {time.ctime(int(f[6:16])):<21} {os.path.getsize(f'{backup_dir}/{f}') / 1024:>10.2f} - {f}")
        elif restore:
            backup_files = sorted([f for f in os.listdir(backup_dir) if f.startswith("hosts")], reverse=True)

            if not backup_files:
                print(f"No backup files found in '{backup_dir}'.")
                return

            if restore == "last":
                restore_file = backup_files[0]
            else:
                restore_file = restore

            if restore_file in backup_files:
                self.clear_entries(with_backup=False)

                with open(f"{backup_dir}/{restore_file}", "r") as backup_file:
                    backup_lines: list[str] = backup_file.readlines()

                with open(hostsfile, "r") as hosts_file:
                    hosts_lines: list[str] = hosts_file.readlines()

                self.start_markers_index, self.end_markers_index = self._find_markers()

                with open(hostsfile, "w") as hosts_file:
                    for i, line in enumerate(hosts_lines):
                        hosts_file.write(line)
                        if line == self.START_MARKER:
                            hosts_file.writelines(backup_lines)

                print(f"Restored backup file '{restore_file}' to '{hostsfile}'.")
            else:
                print(f"Backup file '{restore_file}' not found in '{backup_dir}'.")
        elif remove:
            backup_files = sorted([f for f in os.listdir(backup_dir) if f.startswith("hosts")], reverse=True)

            if remove == "all":
                for f in backup_files:
                    os.remove(f"{backup_dir}/{f}")
                print(f"Removed all backup files from '{backup_dir}'.")
            else:
                if remove == "last":
                    remove_files = backup_files[:1]
                elif remove == "oldest":
                    remove_files = backup_files[-1:]
                else:
                    remove_files = [f for f in backup_files if f == remove]

                for f in remove_files:
                    os.remove(f"{backup_dir}/{f}")
                print(f"Removed {len(remove_files)} backup files from '{backup_dir}'.")
        else:
            self._save_backup_of_hosts_file()


def main():
    parser = argparse.ArgumentParser(
        description="Manage the hosts file."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subparser for the 'add' command
    add_parser = subparsers.add_parser("add", help="Add an ip and hostname to the hosts file")
    add_parser.add_argument("ip", help="The ip address to add")
    add_parser.add_argument("hosts", help="The hostnames to add", nargs="+")

    # Subparser for the 'del' command
    del_parser = subparsers.add_parser("del", help="Delete an IP or hostname from the hosts file")
    del_parser.add_argument(
        "identifier", help="The ip address or hostname to delete. You can also use a regex pattern to match entries ("
                           "e.g. '192.168.* or 'raspi-.*.com')"
    )

    # Subparser for the 'clear' command
    subparsers.add_parser("clear", help="Clear all entries from the hosts file")

    # Subparser for the 'list' command
    l_parser = subparsers.add_parser("list", help="List all entries from the hosts file")
    l_parser.add_argument(
        "--section", "-s", help="Only list entries from the managed section", action="store_true")
    l_parser.add_argument(
        "--sort-by", "-b", help="Sort the entries by ip or hostname (default: ip)",
        choices=["ip", "hostname"], default="ip"
    )
    l_parser.add_argument("--ping", "-p", help="Display the status of the ip addresses", action="store_true")
    l_parser.add_argument("identifier", help="The ip address or hostname to list", nargs="?")

    update_parser = subparsers.add_parser("update", help="Update an entry in the hosts file")
    update_parser.add_argument("identifier", help="The ip address or hostname to update")
    update_parser.add_argument("--ip", help="The new ip address")
    update_parser.add_argument("--hostname", help="The new hostname")

    backup_parser = subparsers.add_parser("backup", help="Backup the hosts file")
    backup_parser.add_argument("--dir", help="The directory to store the backups", default=HostsFile.BACKUP_DIR)
    backup_parser.add_argument("--file", help="The path to the hosts file", default=HostsFile.HOST_FILE)

    backup_exclusive_group = backup_parser.add_mutually_exclusive_group()
    backup_exclusive_group.add_argument("--list", '-l', help="List backups", nargs="?", type=int, const=10)
    backup_exclusive_group.add_argument("--restore", '-r', help="Restore a backup file", nargs="?", const="last")
    backup_exclusive_group.add_argument("--remove", '-x', help="Remove a backup file", nargs="?", const="oldest")

    parser.add_argument("--file", help="The path to the hosts file", default=HostsFile.HOST_FILE)
    args = parser.parse_args()

    hosts_manager = HostsFile(args.file)

    if args.command == "add":
        hosts_manager.add_entries(args.ip, args.hosts)
    elif args.command == "del":
        if hosts_manager.remove_entry(args.identifier):
            print(f"Deleted '{args.identifier}' from hosts file.")
        else:
            print(f"No matching entries found for '{args.identifier}' in the section managed by this script.")
    elif args.command == "clear":
        if hosts_manager.clear_entries():
            print("Cleared all entries from hosts file.")
        else:
            print("No entries found to clear.")
    elif args.command == "list":
        if not hosts_manager.list(
                identifier=args.identifier, in_only_section=args.section,
                sort_by=args.sort_by, ping=args.ping
        ):
            print("No entries found.")
    elif args.command == "update":
        hosts_manager.update_entry(args.identifier, new_ip=args.ip, new_hostname=args.hostname)
    elif args.command == "backup":
        hosts_manager.backup(args.file, args.dir, args.list, args.restore, args.remove)


if __name__ == '__main__':
    main()
