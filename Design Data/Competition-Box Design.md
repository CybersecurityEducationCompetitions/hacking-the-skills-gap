# Random VM things

### Easy Windows (Workstation) - 192.168.1.222

Operating System: Windows 7 - Non domain joined

**Primary Attack Path**:
Eternal Blue Kernel Mode RCE (MS17-010)
Information about this exploit can be found on the Microsoft official security bulletin [here](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)

**Summary:**
Candidates will exploit a Windows workstation vulnerable to the Eternal Blue kernel-mode Remote Command Execution (RCE) vulnerability. This exploit will be the primary attack path to SYSTEM privileges from an unauthenticated context. Other misconfigurations will exist, including misconfigurations part of the original attack path that can be categorized as individual risk. This includes anonymous SMB binding to shares with low-level user credentials, The usage of SMBv1, and an insecure password policy.

**Configurations Requirements:**

- A version of Windows 7 not including the - Security Update for Microsoft Windows SMB Server (Patch number 4013389), publicized March 14, 2017
- SMBv1 Enabled (Should be default but I'll leave cmd just in case)
    - `dism /online /enable-feature /featurename:FS-SMB1 /all /norestart`
    - Reboot - `shutdown /t 0 /r`
- Create share with creds and anon bind
    - Create dir `mkdir C:\\SharedFolder`
    - Make SMB share `net share SharedFolder=C:\SharedFolder`
    - Grant access `icacls "C:\\SharedFolder" /grant Everyone:F`
    - Allow anon binds for smb service in general `reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 1 /f`
    - Then start and stop the workstation service with net `net stop workstation & net start workstation`
    - Create user `net user Sensitiveuser P@ssw0rd /add`
    - put creds into share `echo Sensitiveuser:P@ssw0rd > C:\\SharedFolder\\creds.txt`

### Medium Windows (Domain Controller)

Operating System: Window Server 2019 - Domain Controller

**Primary Attack Path:**

- Anonymous bind to LDAP to pull domain user accounts ->
- Utilize either impackets [GetNPUsers.py](http://getnpusers.py/) or netexec to ASREProast the list of pulled user accounts
- Crack the ticket in hashcat
- Utilize the plaintext domain user credentials to perform a kerberoasting attack on the default Domain Admin account

**Summary:**
Candidates will exploit a Windows Domain Controller in an Active Directory environment by gaining environmental context through service misconfiguration and obtain privilege escalation through multiple Kerberos centric vulnerabilities. These vulnerabilities include ASREPRoasting and Kerberoasting

**Configuration Requirements:**

- An Active Directory forest has been created on the server
- Anonymous LDAP binding set:
    - modify the `dsHeuristics` attribute on the `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,Root domain in forest` object, setting the seventh character to "2" (0000002)
- User generation:
    - `net user <user> <password> /add` for all the user accounts.
- Set DONT_REQ_PREAUTH on a user account with easily crackable credentials
    - Navigate to Active Directory Users and Computers (ADUC) in server manager. Right click a user and select properties, then select the account tab and check mark "Do not require kerberos pre authentication" and click ok/apply
- Set the Domain Admin Kerberoastble, this can be done by adding a `servicePrinicpalName` to the account
    - `setspn -S HTTP/dcfqdn domain\\Administrator`

### Hard Windows

Operating System: Windows Server 2019 - Domain Controller

**Primary Attack Path:**

- A template misconfiguration allows a low privilege user to request a certificate as any domain user by using `ENROLLEE_SUPPLIES_SUBJECT` to specify an arbitrary `SubjectAltName` (ESC1)

Candidates will exploit a Windows Domain Controller in an Active Directory environment under an assumed breach, low privilege user context. This will be performed via privilege escalation through Active Directory Certificate Services (ADCS).

**Configuration Requirements:**

- An Active Directory forest has been created on the server
- A Certification Authority (CA) has been installed on the server
- A template has been created with enrollment access to "Domain Users" or "Everyone" and `ENROLLE_SUPPLIES_SUBJECT`. This can be done through the certification authority menu in server manager.
- A low privilege user has been created for usage. `net user low-priv P@ssw0rd /add`

[fLAGS](https://www.notion.so/fLAGS-1e30e47d480880a489b8d9f802f7b3fe?pvs=21)

## Easy Linux: Command Injection + FTP - 192.168.1.176

- Website Created.
    - Need to change user to “library_admin” which will limit to library home directory
    - Make shadowers or ETC world readable
    - Uninstall SSH
    - Change Sysetmctl service file to run as library_admin.
    - “head -n 20” can allow the user to read shadowers fully. This defeats the purpose of command injection. Need to figure that out. (Maybe a modified version of head that removes the lines command [https://github.com/coreutils/coreutils/blob/master/src/head.c](https://github.com/coreutils/coreutils/blob/master/src/head.c)?)
    - Create FTP Banner for login
        - Anonymous is bonus
            - Add Bonus Flag
        - library - User with no password - has the books
            - FTP Banner says how has a thank you message for getting the books
            - Change directory Books
        - Intern
            - Completed Folder:
                - Source Code for Terminal
                - Source Code for read10 file
            - ToDo:
                - Net Admin Email that contains the hint saying the following:
                    - We need a secret way to send sensitive information in our emails. Hashes won’t work so we need something that’s RANDOM! Figure it out
            - WiP:
                - Terminal.txt:
                    - A file describing how they’re working on the library terminal. It needs to add picture support and probably some security
                - Login.php
                    - Not the actual code, but the pseduo/outline for the login page to the email server. Needs to have users that will be able to be signed into.
                - salaryOffer.pdf - Silly PDF - Nothing important
        - Admin.Mickey
            - Network Map showing the Email/Token Server - The next IP
            - Official Flag

Passwords:

intern : myhero!

libTerminal : Fa58VmY9S - SEUCRE

library : library

Admin.Mickey : heeheehaha

root : employee (lock this) - SECURE

Flags:

FLAG{All_he-had_to_do_was_google_it?}

FLAG{You_Trust_The_Intern_Too_Much}

## Medium Linux Machine - 192.168.1.180

- User is given a webpage. Needs to do an SQL injection to access the page. The username will not be “admin” but something else and the injection will need to be modified to represent that as shown here: [https://app.hackthebox.com/5091fb2a-2e6f-4745-b675-65d4ec2f4794](https://app.hackthebox.com/5091fb2a-2e6f-4745-b675-65d4ec2f4794)

- Once accessed, they will be shown an email-like UI. Multiple emails here with the following (changes based on the user they signed in as): - [https://hub.docker.com/r/changemakerstudiosus/papercut-smtp](https://hub.docker.com/r/changemakerstudiosus/papercut-smtp) or [https://github.com/maildev/maildev](https://github.com/maildev/maildev) (Forward request with correct credentials)
    - CTF Flag Email: An email containing the a tokenized version of the flag, the student will have to detokenize it given the information in other emails or maybe EXFIL data? (THIS WILL BE THE PASSWORD TO THE SSH DOCKER CONTAINER)
    - Docker Escape Hint: Explaining how the next box is in a docker environment
    - A network map the student will have to read. The map will contain the location of the tokenize server the student will have to make API calls too (or use NMAP to find this - since it’s running on a random port)
    - An email with a steganography picture. The theme here is ways to hide information without encrypting it. (This can be in another users email)
    - An email with a ROT cipher? - Trying to get a CyberChef intro here.
    - We’ll have some SPAM emails as well just as a distraction.

SQL Webpage only works with Username

Email Server with emails

Need to do:

- Lock Root/Change password
- Change SQL Database Passwords
- Add CYberChef to Ref Sheet
- Change interface to DHCP
- Remove SSH

Mickey.Admin:

- Email from Head Librarian saying they read a book on Docker Containers and want to move the main server that has all the secret books into dockerization for “security”
- Email from intern Stewie saying they’re trying out different “hiding information” techniques and will be sending a him a bunch of different email with various hiding techniques to see which one is the best ROT13FLAG
- Email with Mike asking Mickey to make sure the files within the main server are not accessible to everyone and that this new “containerzation” thing can’t be escaped from as he read that in a book the head librarian told him to read.
- Network Map
- Tokenization Doc

Stewie:  

- Email from Admin Mickey saying that he needs to find different methods to hide sensitive information.  BASE645FLAG in EXIL
- Email from Head. Librarian thanking him for putting up the Library Terminal up so quickly. Maybe will think about paying him.

Head.Librian:

- Email from Mickey with a <FLAG_TOKEN> letting the Head.Librarian know that they’re confident in this new method Stewie found to hide information
- Email from Mike saying that the intern didn’t explain how to use the information hiding technology/server and instructions on how to use it (tokenization). He doesn’t have the server information yet, but will send once gets the information from Mickey

Mike:

- Email from Mickey with a network map with of the environment. This will contain the IP of the token server and the docker server. : BinaryFLAG?
- Email from Stewie with the website “CyberChef” explaining how it’s a cool site where you can try different hashing, encoding, ecrpytionj, cryptographic algorithms and it’s what he’s using to try to hide the sensitive information.
- Email from Stewie saying how Mike is one of his friends at the library.

Catalog:

- An email from Stewie asking the owner of the catalog to put an image <INSERT STEG IMAGE FLAG> to put in the next newsletter for people to win a prize if they can find out what the picture means.
- Email from the head.librarian asking the catalog owner to start sending newsletters containing information for new books.
- Spam Email

SQLITE3 Database:

1|mickey|ffa6319d6e73c595799cf96c06acc57d|mickey@nonprofit.library
2|stewie|882559e2772f73e91b7c234d256eaf31|stewie@nonprofit.library
3|catalog|8a1f9c155b8bd257ffc2d6d4653e3304|catalog@nonprofit.library
4|mike|a811fc4350e961f8a619541601f00ee8|mike@nonprofit.library
5|head.librarian|9e1d2876024105b08bf503078f8369eb|head.librarian@nonprofit.library

Flags:

ROT13: FLAG{ThisButSensitiveInformationYeah?}

Base64 Flag: RkxBR3tTdGV3aWUgPSBObyBwYXkufQ== (FLAG{Stewie = No pay.})

Steg Flag: FLAG{Put_A_Password_On_The_Picture_Next_Time}

Token Flag (ACTUAL): 5kn6gMB3BWFeDWuR3pBM7jT86g8mePWq = FLAG{If_You_Give_A_Moose_A_Muffin_>_If_You_Give_A_Mouse_A_Cookie}

send proper instructions 

/tokenize/string

/detokenize/string

/deletetoken/string - Not advertised. 

token.service = token API

loginpage.serivce = mail login

NEED TO FIX THE TIMINGS OF EMAILS

Login:

employee : Fa58VmY9S 

Services:

loginpage.service = sqlweb

token.service = token server

Process:
Access webpage at IP:8080

## Hard Linux Machine - 192.168.1.199

- Will combine all 3 methods
- Docker running SSH. This container will use default creds - Need to use Hyrda to brute force the SSH.
    - Need to update hints in #2 to say that the docker container will have a default password for SSH
- Accessed container, will have a README explaining some hint on docker escape is the volume
    - CTF{Docker_Is_Secure}
- Escape the docker volume by mounting host root, then get the secret_books_file.
- The flag will is HEX encoded into the fil
    - Flag is FLAG{Old_Habits_Die_Hard}

Add files to gitabl

create STEWIE account.

Two containers 

 One is the Gitea Container 

- Remove SSH
- Stewie will be the one with an account
- Hide Admin.Mickey Password in Dockerfile
- Upload the README and Dockerfile

One is the vulnerable container:

- Has SSH, they access, and must “escape”
- Make SSH Brute Forceable
- Make start on boot/restart on boot.

Current Process:

Access SSH container on SSH 2222 

See /hosts_secrets is there but cant be accessed.

Create docker container with mounted file system with docker run -it -v /:/hostfs debian bash

Access files in /Books

Use docker cp to pull files out

Use strings or something to grab the flag 🙂

docker run  --name vault -d -p 2222:22 -v /var/run/docker.sock:/var/run/docker.sock -v /opt/Secret_Books:/Books:ro --restart unless-stopped vault 

hydra -l Intern.Stewie -P /usr/share/wordlists/rockyou.txt -s 2222 192.168.1.185 ssh 

- Flag is FLAG{Old_Habits_Die_Hard}
- CTF{Docker_Is_Secure}

Passwords:

Gitea: Admin.Mickey / \zeJd!4313Qa

Gitea: Intern.Stewie / p@ssw0rd 

System: mainServer / \zeJd!4313Qa

System: root / \zeJd!4313Qa

Docker Container: Intern.Stewie : p@ssw0rd 

Docker Container:

Linux Easy: 192.168.1.180:5000 - START

Linux Med: 192.168.1.132:2222 - START

Linux Hard: 192.168.1.185:9999 - START

Kali Boxes:

T1: kali01 / kali01 - 192.168.101.10

T2: kali02 / kali02 - 192.168.101.20