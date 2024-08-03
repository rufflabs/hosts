# Hosts File Manager

This script manages the `/etc/hosts` file, allowing you to add, delete, list, update, backup, and restore entries.

> Inspired by the repository [hosts](https://github.com/rufflabs/hosts) by [rufflabs](https://github.com/rufflabs).

> **Warning**: Use this script with caution as it can modify system files, potentially disrupting network connections.
> Do not rely solely on the backup feature of this script to restore the hosts file in emergencies. Always maintain an independent backup of the original file.
> This script is designed to edit a specific section of the hosts file, but its behavior is not guaranteed.

## Demo Environment

To try out the script in an isolated environment without making changes to your system, you can use Docker. The following command sets up a demo environment where you can experiment with the script:

```sh
docker run -it --rm --hostname hosts-manager python:3.12-slim bash -c "apt-get update && apt-get install -y iputils-ping && pip install pipx && pipx install hosts-manager && pipx ensurepath && export PATH=\$PATH:/root/.local/bin && bash"
```

This command:
- Creates a temporary container with Python 3.12-slim.
- Installs `iputils-ping` to enable the ping feature.
- Installs `pipx` and the `hosts-manager` package.
- Adds the local bin directory to the PATH and opens a bash shell for you to interact with the script.

![Demo Environment with hosts help](https://github.com/Friedjof/hosts/blob/main/media/hosts-help_demo-env.png)
![Demo Environment with hosts list](https://github.com/Friedjof/hosts/blob/main/media/hosts-list_demo-env.png)
![Demo Environment with hosts ping](https://github.com/Friedjof/hosts/blob/main/media/hosts-backup_demo-env.png)

## Installation

Ensure Python >=3.12 is installed on your system. You can install the script using `pip`, `pipx`, or directly from the source code.

### Installing via GitHub

```sh
git clone https://github.com/Friedjof/hosts.git
cd hosts
pip install -r requirements.txt
```

### Installing via pip

You can install the package directly from PyPI:

```sh
pip install hosts-manager
```

### Installing via pipx

Alternatively, you can install the package using `pipx` for isolation:

```sh
pipx install hosts-manager
```

### Installation Using Makefile

The provided `Makefile` simplifies the build, installation, and testing process. Below are the steps to use the `Makefile`:

1. **Build the Package**:
   This command will create source and wheel distributions of the package.
   ```sh
   make build
   ```

2. **Install the Package Using pipx**:
   This command installs the package in an isolated environment using `pipx`.
   ```sh
   make install
   ```

3. **Install the Package in a Virtual Environment**:
   Alternatively, you can install the package in a virtual environment.
   ```sh
   make install-venv
   ```

4. **Uninstall the Package Using pipx**:
   This command uninstalls the package from the `pipx` environment.
   ```sh
   make uninstall
   ```

5. **Uninstall the Package from the Virtual Environment**:
   This command uninstalls the package from the virtual environment.
   ```sh
   make uninstall-venv
   ```

6. **Clean the Build Artifacts**:
   This command removes the build artifacts and temporary files.
   ```sh
   make clean
   ```

7. **Run Tests Using tox**:
   This command runs the tests defined in the `tox` configuration.
   ```sh
   make test
   ```

8. **Upload the Package to PyPI**:
   This command uploads the built distributions to PyPI using `twine`.
   ```sh
   make upload
   ```

9. **Run the Script Directly**:
   This command runs the main script directly.
   ```sh
   make run
   ```

## Usage

The script supports various commands to facilitate the management of the hosts file. Each command has its own parameters and options.

### Commands

- **add**: Adds an IP address and one or more hostnames to the hosts file.
- **del**: Deletes an IP address or hostname from the hosts file.
- **clear**: Clears all entries from the hosts file.
- **list**: Lists all entries from the hosts file.
- **update**: Updates an existing entry in the hosts file.
- **backup**: Backs up the hosts file and offers options to restore or remove backups.

### Options

- **--file**: The path to the hosts file (default: `hosts`).

### Examples

#### Add an IP address and hostname to the hosts file

```sh
hosts add 10.10.10.5 raspi-1.local
hosts add 10.10.10.4 raspi-2.local raspi-3.local raspi-4.local
```

#### Update an entry in the hosts file

```sh
hosts update raspi-1.local --ip 10.10.10.1
hosts update 10.10.10.1 --hostname raspi-10.local
hosts update 10.10.10.* --ip 10.10.10.10
hosts update raspi-.*.local --hostname raspi-10.local --ip 10.10.10.10
```

#### Delete an IP address or hostname from the hosts file

```sh
hosts del 10.10.10.5
hosts del raspi-1.local
hosts del 10.10.10.*
hosts del raspi-.*.local
```

#### Clear all entries from the hosts file

```sh
hosts clear
```

#### List all entries from the hosts file

```sh
hosts list
hosts list --section
hosts list --section --sort-by hostname
hosts list 10.10.10.* -s -b hostname
hosts list --ping
```

#### Backup the hosts file

```sh
hosts backup
hosts backup --file /etc/hosts --dir ~/.local/share/hosts
hosts backup --list 5
hosts backup --restore
hosts backup -r hosts-1631533200.bak
hosts backup --remove last
hosts backup -x oldest
hosts backup -x hosts-1631533200.bak
hosts backup --remove all
```

## Parameters

### General Parameters

- **--file**: The path to the hosts file (default: `/etc/hosts`).

### `add` Command

- **ip**: The IP address to add.
- **hosts**: The hostnames to add (separate multiple hostnames with spaces).

### `del` Command

- **identifier**: The IP address or hostname to delete. Supports regex patterns (e.g., `192.168.*` or `raspi-.*.com`).

### `clear` Command

- No additional parameters.

### `list` Command

- **--section**, `-s`: Only list entries from the managed section.
- **--sort-by**, `-b`: Sort the entries by IP address or hostname (default: `ip`).
- **--ping**, `-p`: Display the status of the IP addresses.
- **identifier**: The IP address or hostname to list (optional).

### `update` Command

- **identifier**: The IP address or hostname to update.
- **--ip**: The new IP address.
- **--hostname**: The new hostname.

### `backup` Command

- **--dir**: The directory to store the backups (default: `HostsFile.BACKUP_DIR`).
- **--file**: The path to the hosts file (default: `HostsFile.HOST_FILE`).

Mutually exclusive options:
- **--list**, `-l`: List backups.
- **--restore**, `-r`: Restore a backup file (optional: specific file).
- **--remove**, `-x`: Remove a backup file (optional: specific file or `oldest`, `last`, `all`).

## Contributing

If you find any issues or have feature requests, feel free to open an [issue](https://github.com/Friedjof/hosts/issues). Pull requests are also welcome!

## More Information

For detailed information on using each command and available parameters, run the script with the `--help` parameter:

```sh
hosts --help
```