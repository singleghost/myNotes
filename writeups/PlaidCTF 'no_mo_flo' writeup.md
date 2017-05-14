# PlaidCTF 'no_mo_flo' writeup

这道题是一道比较简单的逆向，代码做了混淆。题目读取32个字节的输入，分成下标为偶数的一组和下标为奇数的一组，然后分别对这两组做判断。

对下标为偶数的一组进行判断的代码反汇编只能看到一个 JUMPOUT，观察汇编代码发现函数里面有很多 jmp 指令，jmp 到一个地址，而那个地址是执行`jmp r11`这条指令，而`r11`的值是通过在一开始的 jmp 指令之前通过`lea r11`来设置的，`r11`的值就是实际的 jmp 地址。为了让 ida 能够成功对函数进行反汇编，需要把这些指令都替换掉，改成直接 jmp 到目标地址。这就需要用到 idapython 了，由于 jmp 指令的操作数实际上是下一条指令地址到目标地址的偏移，所以这个脚本写起来还是有点麻烦的，而且程序中还用到了`jnz`, `jz`等指令，还需要分情况讨论。

```python
import patch_utils
import struct

def u8(string):
    return struct.unpack('b', string)[0]

def u32(string):
    assert(len(string) == 4)
    return struct.unpack('i', string)[0]

def p32(value):
    return struct.pack('i', value)

def patch_jumps(start, end, max_inst_len):
    ea = start
    count = 0
    while ea < end:
        cur_bytes = idc.GetManyBytes(ea, max_inst_len)
        if isJmp2_400F10(ea, cur_bytes):
            print 'Patching addr {}'.format(hex(ea))
            do_patch_jump(ea, cur_bytes)
            count += 1
        ea = idc.NextHead(ea)
    print 'Done patch, {} patched'.format(count)

'''
instruction starts with                 inst_Length
'\xE9' is jmp 0x00000000                5
'\x0f\x84' is jz 0x00000000             6
'\xEB' is jmp short 0x00                2
'\x74' is jz short 0x00                 2
'\x0f\x85' is jnz 0x12345678            6
'''
op2len = {
        '\xE9': 5,
        '\x0f\x84': 6,
        '\xEB': 2,
        '\x74': 2,
        '\x0f\x85': 6,
        '\x4c\x8d\x1c\x25': 8   #lea r11, 0x12345678
        }

def isJmp2_400F10(cur_ea, inst_bytes):
    global op2len
    target = 0x400f10
    if inst_bytes.startswith('\xE9'):
        offset = u32(inst_bytes[1:5])
        if cur_ea + op2len['\xE9'] + offset == target:
            return True
    elif inst_bytes.startswith('\x0f\x84'):
        offset = u32(inst_bytes[2:6])
        if cur_ea + op2len['\x0f\x84'] + offset == target:
            return True
    elif inst_bytes.startswith('\xEB'):
        offset = u8(inst_bytes[1])
        if cur_ea + op2len['\xEB'] + offset == target:
            return True
    elif inst_bytes.startswith('\x74'):
        offset = u8(inst_bytes[1])
        if cur_ea + op2len['\x74'] + offset == target:
            return True
    elif inst_bytes.startswith('\x0f\x85'):
        offset = u32(inst_bytes[2:6])
        if cur_ea + op2len['\x0f\x85'] + offset == target:
            return True

    return False

def do_patch_jump(ea, inst_bytes):
    global op2len
    lea_inst = idc.GetManyBytes(ea - 8, 8)
    if not lea_inst.startswith('\x4c\x8d\x1c\x25'):
        return False

    r11 = u32(lea_inst[4:])
    if inst_bytes.startswith('\xE9'):
        offset = r11 - (ea + op2len['\xE9'])
        new_inst = '\xE9' + p32(offset)
        new_inst = new_inst.ljust(8+op2len['\xE9'], '\x90') #padding with nop
        """
        patch
        lea r11, loc_400df2     => jmp 0x12345678
    ea->--------------------------------------------
        jmp loc_400f10          => nop
                                => nop
                                => ...
        """
        do_patch_bytes(ea-8, new_inst )
    elif inst_bytes.startswith('\x0f\x84'):
        offset = r11 - (ea + op2len['\x0f\x84'])
        new_inst = '\x0f\x84' + p32(offset)
        new_inst = new_inst.ljust(8+op2len['\x0f\x84'], '\x90')
        do_patch_bytes(ea-8, new_inst)
    elif inst_bytes.startswith('\xEB'):
        offset = r11 - (ea + op2len['\xEB'])
        new_inst = '\xE9' + p32(offset)
        new_inst = new_inst.ljust(8+op2len['\xEB'], '\x90')
        do_patch_bytes(ea-8, new_inst)
    elif inst_bytes.startswith('\x74'):
        offset = r11 - (ea + op2len['\x74'])
        new_inst = '\x0f\x84' + p32(offset)     #jz 0x12345678
        new_inst = new_inst.ljust(8+op2len['\x74'], '\x90')
        do_patch_bytes(ea-8, new_inst)
    elif inst_bytes.startswith('\x0f\x85'):
        offset = r11 - (ea + op2len['\x0f\x85'])
        new_inst = '\x0f\x85' + p32(offset)
        new_inst = new_inst.ljust(8+op2len['\x0f\x85'], '\x90')
        do_patch_bytes(ea-8, new_inst)


patch_jumps(0x4006c6, 0x400f13, 6)
do_patch_function('\xE9\x00\x00\x00\x00', '\x90'*5, 0x4006c6)   #patch jmp $+5 to `nop`
do_patch_function('\x41\xb8\x00\x00\x00\x00', '1\xc0H\x83\xc4\x08\xc3'.ljust(11, '\x90'), 0x4006c6)
#patch `mov r8d, 0;...` to `xor eax,eax;add rsp,8;ret`
```

patch 之后会发现程序中仍然存在很多`jmp $+5`的指令，因为 jmp 指令本身的长度就是5，这条指令就是等于什么都没有做，所以可以把这些指令都批量 nop 掉。但是 F5还是没法正确反编译。仔细观察发现程序中对一个字符如果判断是不正确的话就会`mov r8d, 0`，最后函数返回的时候会把`r8d`赋值给`eax`，所以可以把这个 patch 成直接置 eax 为0，然后返回。

这样再反编译就成功了。

```C
void __fastcall judge_evens(_DWORD *a1)
{
  __int64 v1; // rax@23

  if ( *a1 == 'P'
    && *a1 != 'V'
    && a1[1] != 'S'
    && a1[1] == 'T'
    && a1[2] != ('|')
    && a1[2] == '{'
    && 2 * a1[3] == 96
    && a1[4] == 'f'
    && 2 * a1[5] == 96
    && 3 * a1[5] == 144
    && a1[6] == '_'
    && a1[6] != ';'
    && a1[7] == '0'
    && a1[8] != 'k'
    && a1[8] == 'l'
    && a1[9] == 'k'
    && a1[10] == '_'
    && a1[10] != '^'
    && a1[11] == 'h'
    && a1[12] >> 1 == 52
    && a1[13] == 108
    && a1[14] == '_' )
  {
    v1 = a1[15] == '0';
  }
}
```



然后是奇数组，奇数组比较麻烦。程序在一开始设置了SIGFPE这个信号的 sigaction 函数。在比较完一个字符之后会调用`idiv ds:qword_603320`这条指令，而`ds:qword_603320`的值是0，除0会抛出 SIGFPE 信号，然后就跳转到 sigaction 函数里去了。在这个函数里会对 cmp 的结果进行判断，决定是跳转还是不跳转。



```assembly
00000000400F40                 cmp     eax, 40h;字符比较
.text:0000000000400F43                 lea     r10, loc_401028;如果判断成功，跳转到的地址
.text:0000000000400F4B                 mov     r11, 5; 决定sigaction函数里走哪条 switch case
.text:0000000000400F52                 mov     dword ptr ds:qword_603328, 1
.text:0000000000400F5D                 mov     ds:qword_603330, rax
.text:0000000000400F65                 mov     rax, 0
.text:0000000000400F6C                 mov     ds:qword_603338, rdx
.text:0000000000400F74                 lea     rdx, loc_400F7B
.text:0000000000400F7B
.text:0000000000400F7B loc_400F7B:                             ; DATA XREF: judge_ords+5Co
.text:0000000000400F7B                 mov     ds:rip_save, rdx
.text:0000000000400F83                 cdq
.text:0000000000400F84                 idiv    ds:qword_603320	;在这里触发SIGFPE信号
.text:0000000000400F8C                 mov     ds:qword_603320, 0
.text:0000000000400F98                 mov     rax, ds:qword_603330
.text:0000000000400FA0                 mov     rdx, ds:qword_603338
.text:0000000000400FA8                 mov     r11, ds:qword_603340
.text:0000000000400FB0                 jmp     r11
.text:0000000000400FB0 judge_ords      endp
```

而 sigaction 函数也比较有意思，这个函数里面每一条 switch 的函数都是在判断EFLAGS这个寄存器的某一个标志位的情况。

```C
switch ( _r11 )
    {
      case 1LL:                                 // JGE就失败
        LODWORD(_r11) = JGE_2fail(_rip, eflags);// 错误的分支
        break;
      case 2LL:
        LODWORD(_r11) = sub_40289A(_rip, eflags);
        break;
      case 3LL:                                 // JG
        LODWORD(_r11) = JG_2success(_rip, eflags);
        break;
      case 4LL:
        LODWORD(_r11) = sub_4029D4(_rip, eflags);
        break;
      case 5LL:                                 // JE
        LODWORD(_r11) = JE_2success(_rip, eflags);// cmp 相等走这里是正确的分支
        break;
      case 6LL:
        LODWORD(_r11) = sub_402AB0(_rip, eflags);
        break;
      case 7LL:                                 // JMP
        LODWORD(_r11) = JMP(_rip);
        break;
      default:
        break;
    }
```

以 case 1为例，如果 OF 标志位和 SF 标志位相等就走错误的分支，这个函数本质上就相当于`JGE`这一条指令。

```C
  if ( (eflags & 0x800) > 0LL == (eflags & 0x80) > 0LL )// OF和 SF 一样
  {
    result = (rip_save + 56);
    qword_603340 = (rip_save + 56);
  }
```

这样就完全理解了程序的意图了，之后就是体力活了。

flag: `PCTF{n0_fl0?_m0_like_ah_h3ll_n0}`

## 参考文献

1. [EFLAGS寄存器详解](http://blog.csdn.net/jn1158359135/article/details/7761011)
2. [signal handler](http://blog.csdn.net/jn1158359135/article/details/7761011)