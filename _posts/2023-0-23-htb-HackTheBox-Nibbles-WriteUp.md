---
layout: single
title: Nibbles - Hack The Box
excerpt: ""
date: 2023-07-23
classes: wide
header:
  teaser: /assets/images/htb-writeup-nibbles/nibbles_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Easy
  - Web Enumeration
  - Basic Linux knowledge
---

![](/assets/images/htb-writeup-nibbles/nibbles_logo.png)

Delivery is a quick and fun easy box where we have to create a MatterMost account and validate it by using automatic email accounts created by the OsTicket application. The admins on this platform have very poor security practices and put plaintext credentials in MatterMost. Once we get the initial shell with the creds from MatterMost we'll poke around MySQL and get a root password bcrypt hash. Using a hint left in the MatterMost channel about the password being a variation of PleaseSubscribe!, we'll use hashcat combined with rules to crack the password then get the root shell.

## VPN connection

To begin exploring the Nibbles machine, we use the following one-liner to run OpenVpn with the specified VPN file:
```bash
    sudo openvpn {vpnFile}
```
Remember to replace `{vpnFile}` with the actual filename of the OpenVPN configuration file. The command allows us to establish a secure VPN connection and gain acces to the target network.

## Portscan

We utilized the tool Nmap to perform a scan on the target IP address:
```bash
$ sudo nmap 10.10.10.75 -p- -sS --min-rate 5000
```

Let's break down each part of the command:

- `sudo`: We used `sudo`to execute Nmap with elevated privileges.
- `nmap`: This command help us to explore the ports on the machine.
- `-p-`: The flag `-p-` instructs Nmap to scall all 65535 ports.
- `-sS`: The flag `-sS`enables TCP SYN scan.
- `--min-rate 5000`: We set the minimun sending rate to 5000 packets per second.

After executing the command, Nmap show us that there are two ports open
```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-23 16:46 CEST
Nmap scan report for 10.10.10.75
Host is up (0.14s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```bash
$ sudo nmap 10.10.10.75 -p 22,80 -sCV -sS --min-rate 5000
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-23 16:56 CEST
Nmap scan report for 10.10.10.75
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4f8ade8f80477decf150d630a187e49 (RSA)
|   256 228fb197bf0f1708fc7e2c8fe9773a48 (ECDSA)
|_  256 e6ac27a3b5a9f1123c34a55d5beb3de9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Website

The Delivery website is pretty basic, there's a link to a vhost called helpdesk.delivery.htb and a contact us section. We'll add this entry to our local host before proceeding further.

![](/assets/images/htb-writeup-delivery/website1.png)

The contact us section tells us we need an @delivery.htb email address and tells us port 8065 is a MatterMost server. MatterMost is a Slack-like collaboration platform that can be self-hosted.

![](/assets/images/htb-writeup-delivery/website2.png)

Browsing to port 8065 we get the MatterMost login page but we don't have credentials yet

![](/assets/images/htb-writeup-delivery/mm1.png)

## Helpdesk

The Helpdesk page uses the OsTicket web application. It allows users to create and view the status of ticket.

![](/assets/images/htb-writeup-delivery/helpdesk3.png)

We can still open new tickets even if we only have a guest user.

![](/assets/images/htb-writeup-delivery/helpdesk1.png)

After a ticket has been created, the system generates a random @delivery.htb email account with the ticket ID.

![](/assets/images/htb-writeup-delivery/helpdesk2.png)

Now that we have an email account we can create a MatterMost account.

![](/assets/images/htb-writeup-delivery/mm2.png)

A confirmation email is then sent to our ticket status inbox.

![](/assets/images/htb-writeup-delivery/mm3.png)

We use the check ticket function on the OsTicket application and submit the original email address we used when creating the ticket and the ticket ID.

![](/assets/images/htb-writeup-delivery/mm4.png)

We're now logged in and we see that the MatterMost confirmation email has been added to the ticket information.

![](/assets/images/htb-writeup-delivery/mm5.png)

To confirm the creation of our account we'll just copy/paste the included link into a browser new tab.

![](/assets/images/htb-writeup-delivery/mm6.png)

After logging in to MatterMost we have access to the Internal channel where we see that credentials have been posted. There's also a hint that we'll have to use a variation of the `PleaseSubscribe!` password later.

![](/assets/images/htb-writeup-delivery/mm7.png)

## User shell

With the `maildeliverer / Youve_G0t_Mail!` credentials we can SSH in and get the user flag.

![](/assets/images/htb-writeup-delivery/user.png)

## Credentials in MySQL database

After doing some recon we find the MatterMost installation directory in `/opt/mattermost`:

```
maildeliverer@Delivery:/opt/mattermost/config$ ps waux | grep -i mattermost
matterm+   741  0.2  3.3 1649596 135112 ?      Ssl  20:00   0:07 /opt/mattermost/bin/mattermost
```

The `config.json` file contains the password for the MySQL database:

```
[...]
"SqlSettings": {
        "DriverName": "mysql",
        "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
[...]
```

We'll connect to the database server and poke around.

```
maildeliverer@Delivery:/$ mysql -u mmuser --password='Crack_The_MM_Admin_PW'
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 91
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mattermost         |
+--------------------+
```

MatterMost user accounts are stored in the `Users` table and hashed with bcrypt. We'll save the hashes then try to crack them offline.

```
MariaDB [(none)]> use mattermost;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mattermost]> select Username,Password from Users;
+----------------------------------+--------------------------------------------------------------+
| Username                         | Password                                                     |
+----------------------------------+--------------------------------------------------------------+
| surveybot                        |                                                              |
| c3ecacacc7b94f909d04dbfd308a9b93 | $2a$10$u5815SIBe2Fq1FZlv9S8I.VjU3zeSPBrIEg9wvpiLaS7ImuiItEiK |
| 5b785171bfb34762a933e127630c4860 | $2a$10$3m0quqyvCE8Z/R1gFcCOWO6tEj6FtqtBn8fRAXQXmaKmg.HDGpS/G |
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
| snowscan                         | $2a$10$spHk8ZGr54VWf4kNER/IReO.I63YH9d7WaYp9wjiRswDMR.P/Q9aa |
| ff0a21fc6fc2488195e16ea854c963ee | $2a$10$RnJsISTLc9W3iUcUggl1KOG9vqADED24CQcQ8zvUm1Ir9pxS.Pduq |
| channelexport                    |                                                              |
| 9ecfb4be145d47fda0724f697f35ffaf | $2a$10$s.cLPSjAVgawGOJwB7vrqenPg2lrDtOECRtjwWahOzHfq1CoFyFqm |
+----------------------------------+--------------------------------------------------------------+
8 rows in set (0.002 sec)
```

## Cracking with rules

There was a hint earlier that some variation of `PleaseSubscribe!` is used.

I'll use hashcat for this and since I don't know the hash ID for bcrypt by heart I can find it in the help.

```
C:\bin\hashcat>hashcat --help | findstr bcrypt
   3200 | bcrypt $2*$, Blowfish (Unix)                     | Operating System
```

My go-to rules is normally one of those two ruleset:

- [https://github.com/NSAKEY/nsa-rules/blob/master/_NSAKEY.v2.dive.rule](https://github.com/NSAKEY/nsa-rules/blob/master/_NSAKEY.v2.dive.rule)
- [https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule](https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule)

These will perform all sort of transformations on the wordlist and we can quickly crack the password: `PleaseSubscribe!21`

```
C:\bin\hashcat>hashcat -a 0 -m 3200 -w 3 -O -r rules\_NSAKEY.v2.dive.rule hash.txt wordlist.txt
[...]
$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21

Session..........: hashcat
Status...........: Cracked
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
[...]
```

The root password from MatterMost is the same as the local root password so we can just su to root and get the system flag.

![](/assets/images/htb-writeup-delivery/root.png)
