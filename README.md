# rootend

rootend is a python *nix Enumerator & Auto Privilege Escalation tool.

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
rootend v.2.0.2 - Enumeration & Automation Privilege Escalation tool.
rootend is an open source tool licensed under GPLv3.
Affected systems: *nix.
Written by: @nickvourd of @twelvesec.
Special thanks to @maldevel & servo.
https://www.twelvesec.com/
Please visit https://github.com/twelvesec/rootend for more..

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show version and exit
  -a, --auto            automated privilege escalation process
  -m, --manual          system enumeration
  -n, --nocolor         disable color
  -b, --banner          show banner and exit
  -s, --suid            suid binary enumeration
  -w, --weak            weak permissions of files enumeration
  -p, --php             PHP configuration files enumeration
  -c, --capabilities    capabilities enumeration
  -f, --full-writables  world writable files enumeration

usage examples:
  ./rootend.py -a
  ./rootend.py -m
  ./rootend.py -v
  ./rootend.py -b

Specific categories usage examples:
  ./rootend.py -a -s
  ./rootend.py -m -w
  ./rootend.py -a -s -p
  ./rootend.py -m -w -c -p
  ./rootend.py -a -s -c -p -f

  *Use the above arguments with -n to disable color.

```

## Version

### 2.0.2

## Supports

* Python 2.x
* Python 3.x

## Tested on

* Python 2.7.18rc1
* Python 3.8.2

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
 * apache2.conf
 * httpd.conf
 * redis.conf
 * /root

### Weak Ownership:
 * /etc/passwd
 * /etc/shadow
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
 * World Writable Files
