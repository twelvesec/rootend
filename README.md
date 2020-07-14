# rootend

rootend is a python 3.x *nix Enumerator & Auto Privilege Escalation tool.

*For a full list of our tools, please visit our website <https://www.twelvesec.com/>*

Written by:

* [nickvourd](https://github.com/nickvourd) ([twitter](https://twitter.com/nickvourd))
* [maldevel](https://github.com/maldevel) ([twitter](https://twitter.com/maldevel))
* [servo](https://github.com/gbkaragiannidis) 



## Usage

```
___________              .__                _________              
\__    ___/_  _  __ ____ |  |___  __ ____  /   _____/ ____   ____  
  |    |  \ \/ \/ // __ \|  |\  \/ // __ \ \_____  \_/ __ \_/ ___\ 
  |    |   \     /\  ___/|  |_\   /\  ___/ /        \  ___/\  \___ 
  |____|    \/\_/  \___  >____/\_/  \___  >_______  /\___  >\___  >
                       \/               \/        \/     \/     \/ 
rootend v.1.5.8 - Enumeration & Automation Privilege Escalation tool.
rootend is an open source tool licensed under GPLv3.
Affected systems: *nix.
Written by: @nickvourd of @twelvesec.
Special thanks to @maldevel & servo.
https://www.twelvesec.com/
Please visit https://github.com/twelvesec/rootend for more..


usage: rootend.py [-h] [-v] [-a] [-m]

optional arguments:
  -h, --help     show this help message and exit
  -v, --version  show version and exit
  -a, --auto     automated privilege escalation process.
  -m, --manual   system enumeration.

usage examples:
  ./root_end.py -a
  ./root_end.py -m
  ./root_end.py -v

  *Use only one argument!

```

## Version

### 1.5.8

## Modes

* Manual
* Auto

## Exploitation Categories

### Suid Binaries:
 * General Suids
 * Suids for reading files
 * Suids for creating file as root
 * Limited Suids
 * Custom Suids

### Weak Permissions:
 * /etc/passwd
 * /etc/shadow
 * /etc/sudoers
 * apache2.conf
 * httpd.conf
 * redis.conf
 * /root

### Weak Ownership:
 * /etc/passwd
 * /etc/shadow
 * /etc/sudoers
 * apache2.conf
 * httpd.conf
 * redis.conf
 * /root

### Capabilities:
 * General Capabilities
 * Custom Capabilities
 * With CAP_SETUID

### Interesting Files:
 * PHP Configuration Files
