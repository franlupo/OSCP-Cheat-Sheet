# Check List

**FTP (21)**
- [ ] Complete Scripted Scan with Nmap
- [ ] Anonymous Login
	- [ ] Download Files
	- [ ] Check files content
		- [ ] Extract usernames with exiftool
	- [ ] Upload Files (potential webshell)
- [ ] Search for Vulnerable FTP versions
- [ ] Bruteforce with Hydra

**SSH**
- [ ] SSH Audit and Vulnerable Version (exploits online)
- [ ] Bruteforce with Hydra

**SMTP**
- [ ] Complete scripted scan with Nmap
- [ ] Send Phishing email (Credentials + Targets)
- [ ] Username Enumeration (smtp-user-enum)

**DNS**

- [ ] Try to extract ifnromation
- [ ] DNS Zone Transfer

**LDAP**

- [ ] Nmap Enumeration
- [ ] Anonymous Bind

**RPC**

- [ ] Anonymous Bind
	- [ ] Domain User/Group/Password Policy Enumeration

**SMB**

 - [ ] Nmap Enumeration (CVEs)
 - [ ] Check for Null/Guest Sessions
	 - [ ] Read Files (Exiftool files)
	 - [ ] Write Files (Potential Webshell)

**HTTP**
- [ ] Google Ports + NMAP + NMAP Scripts
- [ ] Common Software
	- [ ] Public Exploit 
	- [ ] Hacktricks Software
- [ ] Directory Enumeration (Feroxbuster with extensions and recursive)
	- [ ] Lookout for Error Messages/ 500
	- [ ] FFUF + Crawl.py yo find hidden directories on the source code
	- [ ] Best wordlists: Seclist: directory list 2-3big.txt and raft wordlist
- [ ] Subdomain/Vhost Enumeration
- [ ] Login
	- [ ] Default Credentials
	- [ ] View Source Code
	- [ ] Username Enumeration (Login/Forgot Password/Blog Authors)
	- [ ] Try SQL Injection with known usernames
	- [ ] Commons Credentials (Wordlist with admin, administrator, root, box-name)
	- [ ] Dictionary Attack
	- [ ] Register User
	- [ ] Inspect Session Cookie
- [ ] Web Vulnerabilities 
	- [ ] File Upload
		- [ ] Upload Webshell
		- [ ] Directory Bruteforce to find webshell
	- [ ] Command Injection/SSTI
	- [ ] SSRF (All URL Fields)
		- [ ] HTTP request to us + Reverse Shell
		- [ ] 127.0.0.1/Machine IP and every port in search for API
	- [ ] SQL Injection
		- [ ] Run automated detection payloads (https://github.com/payloadbox/sql-injection-payload-list/tree/master/Intruder/detect)
		- [ ] Database Information
		- [ ] Execute Commands
		- [ ] Upload Web Shell
	- [ ] LFI (PHP wrapper, directory transversal)
		- [ ] SSH Files
		- [ ] Software Configuration files 
		- [ ] Log Poisoning
		- [ ] Try to get a reverse locally and see if it executes (PG Snookums)
		- [ ] RFI
- [ ] Inspect Source Code to check for credentials and hidden directories
- [ ] Search configuration files (subdomain enumeration and directory enumeration)
	- [ ] Example .git + git-dumper + grep (LinkVortex)
	- [ ] Read Software Configuration FIles (if we can read files on the machine via SMB/FTP or Path Transversal) -> Search online location of files
- [ ] WebDab -> Cadaver + Credentials -> Webshell

**RDP**

- [ ] Bruteforce

**PostGres**

- [ ] Nmap Enumeration
- [ ] Try some Default credentials
- [ ] Query SNMP

**MySQL**

- [ ] Nmap Enumeration
- [ ] Bruteforce

**SNMP**

- [ ] Nmap Enumeration
- [ ] Try some Default credentials
- [ ] Bruteforce

**SSL**
- [ ] Analyze HTTPS certificate
- [ ] Use openssl to get infromation

**NFS**

- [ ] Nmap Enumeration
- [ ] Check Mountable Shares
- [ ] Mount Shares
	- [ ] Read Files (Exiftool)
	- [ ] Write Files (Potential webshell)
- [ ] No_root_squash privesc

**Unknown Port**
- [ ] Hacktricks
- [ ] Online Exploits
- [ ] Try Default Credentials
- [ ] Netcat to port (help, version)


**Privilege Escalation (Linux)**
- [ ] `su` as every user with shell: without password and with their names as password / SUBRUTE
- [ ] Manual checks
	- [ ] Home Directories Files/opt/web server directory/Local Database
	- [ ] Home (/home)
	- [ ] Web Apps Configuration Files/DBs (/var/www)
	- [ ] Local Ports 127.0.0.1 or IP (netstat -ano)
		- [ ] Check if there is another web server running as another user which we can drop a rev shell and execute or just explore
		- [ ] Or another interesting service such as a Local DB
	- [ ] Environmental Variables
	- [ ] Bash Version Exploits?
	- [ ] Sudo -l
		- [ ] GTFOBins
		- [ ] LD_Preload
		- [ ] LD_LIBRARY_PATH
		- [ ] Unknown Binary
			- [ ] Check Exploit Online (Version)
			- [ ] Check Online for RCE
			- [ ] CHeck Help command to see if you can run code
			- [ ] Strings binary/strings -e binary
			- [ ] strace binary
			- [ ] Run binary to see if its a BOF vector (GDB on machine?)
	- [ ] Check Sudo Version -> CVEs
	- [ ] Privileged Groups 
		- [ ] User part of LXD/LXC Group (HTB Tabby)
		- [ ] User part of disk Group (PG Fanatastic)
		- [ ] User part of docker Group (PG Peppo)
		- [ ] User part of ADM Group (THM K2) -> Can read logs /var/log
	- [ ] Scheduled Tasks
		- [ ] Cron Jobs (search every file) and pay close attention to $PATH and not using full paths
		- [ ] SystemCTL
		- [ ] PSPY 
		- [ ] `watch -n 1 "ps -aux | grep pass"`
	- [ ] SUID Bits (as other users/groups/root)
		- [ ] GTFOBins
		- [ ] Symlinks Nginx Exploit (CVE-2016-1247)
		- [ ] Unknown Binary
			- [ ] Check Exploit Online (Version)
			- [ ] Check Online for RCE
			- [ ] CHeck Help command to see if you can run code
			- [ ] Strings binary/strings -e binary -> Path Hijack?
			- [ ] strace binary -> Share Object Injection?
			- [ ] Run binary to see if its a BOF vector (GDB on machine?)
	- [ ] Important File Permissions (/etc/passwd /etc/shadow /etc/sudoers)
	- [ ] Capabilities
	- [ ] Linux PAM 1.1.0 (HTB PopCorn)
- [ ] Vulnerable Software
	- [ ] Software + Priv Esc Google Search
- [ ] Kernel Exploits
	- [ ] Linpeas (./linpeas -a -e -P password)
	- [ ] Linux Exploit Suggester
	- [ ] Linux Smart Enumeration
	- [ ] Manual kernel search with Google + Exploit-DB
- [ ] SSH
	- [ ] Find Private Keys
	- [ ] Read Private Keys
	- [ ] Writable SSH Keys
- [ ] Manually Search files for credentials
- [ ] Unmounted Filesystems and repeat enumeration
- [ ] NFS no_root_squash
- [ ] Installed packages (dpkg -l /rpm -qa)
- [ ] Specific Unknown Binary
	- [ ] Try -h, --help, -v, --version (might be a known exploitable GTFO binary)
	- [ ] Check for exploits online
		- [ ] Related to Privilege Escalation
		- [ ] Related to Command Execution
	- [ ] strace binary to check if its loading 

**Privilege Escalation (Windows)**
- [ ] Abuse Privileges
	- [ ] SeImpersonatePrivilege
	- [ ] SeAssignPrimaryPrivilege (Juicy)
	- [ ] SeBackup
	- [ ] SeBackupPrivilege/SeRestorePrivilege
	- [ ] SeDebugPrivilege
- [ ] Upload reverse shell to web server and run it via browser to get a shell as service account (PG Craft)
- [ ] Home Directories /web server directory/Local Database
- [ ] Home (/home)
- [ ] Web Apps Configuration Files/DBs (/inetpub)
- [ ] Local Ports 127.0.0.1 or IP (netstat -ano)
	- [ ] Check if there is another web server running as another user which we can drop a rev shell and execute or just explore
	- [ ] Or another interesting service such as a Local DB
- [ ] AlwaysInstalledElevated
- [ ] Check readable SAM SYSTEM SECURITY
	- [ ] VSS
- [ ] Powershell History
- [ ] Services
	- [ ] Insecure Service Permissions
	- [ ] Service Binary Replace
	- [ ] Unquoted Service Path
- [ ] Scheduled Tasks
- [ ] DLL Hijacking
	- [ ] Upload Binary to Windows and execute and analyze with ProcMon
- [ ] Registry Keys
- [ ] Auto-Run
- [ ] Auto-Logon Credentials
- [ ] Files
	- [ ] Password Hunting
	- [ ] Unattended Windows Files
	- [ ] ISS Configuration Files
- [ ] Saved Windows Credentials
- [ ] Startup Application
- [ ] GPP Password
- [ ] Installed Applications
- [ ] Vulnerable Drivers
- [ ] Kernel Exploits
	- [ ] Winpeas
	- [ ] PrivesCheck -Extended
	- [ ] WES

**AD (Windows)**
- [ ] Check user's descriptions
- [ ] Kerbrute
	- [ ] Run Username Enumeration if you have a list of names and access to DC
- [ ] ADPeas
- [ ] BloodHound
- [ ] NXC LDAP Modules
- [ ] NXC SMB Modules
- [ ] New User!
	- [ ] Spray password/hash to other users
	- [ ] Owned in Bloodhound -> Check Privileges/groups/ACL/ACEs -> Owned to DA
	- [ ] Delegation Rights
	- [ ] DC Sync
	- [ ] Check if is admin on any machine using SMB/RDP/WinRM whateverco
- [ ] SMB Sessions we have access to (READ and Write)
- [ ] Kerberoastable
- [ ] ASREP-Roasting
- [ ] If we are dealing with a mail server and have AD accounts we can try to send emails to the other targets and catch a shell with SWAKS (RELIA MAIL)
- [ ] Silver Ticket 
	- [ ] Create when having access to a service account because you can have more privileges when connecting over kerberos than norrmally (PG Nagoya)
- [ ] Golden Ticket
	- [ ] KRBTGT Hash

**Post-Exploitation**
- [ ] Create Admin User
- [ ] Enable RDP
- [ ] Dump LSA, SAM, LSASS
- [ ] WinPEAS
- [ ] Powershell History
- [ ] Ligolo