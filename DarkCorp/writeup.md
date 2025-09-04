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

- change mail recipient to our own email
```name=test&email=test%40drip.htb&message=test&content=text&recipient=test%40drip.htb```



