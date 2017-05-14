# ASISctf2017 'crc' writeup

这道题思路很清晰，存在两处很明显的 gets 函数调用导致栈溢出

```C
int get_userinput_number_vul()
{
  int result; // eax@1
  int v1; // edx@1
  char buf[4]; // [esp+14h] [ebp-38h]@1
  int v3; // [esp+18h] [ebp-34h]@1
  __int16 v4; // [esp+1Ch] [ebp-30h]@1
  int cookie; // [esp+3Ch] [ebp-10h]@1

  cookie = *MK_FP(__GS__, 20);
  *(_DWORD *)buf = 0;
  v3 = 0;
  v4 = 0;
  gets(buf);                                    // 这里有溢出
  result = atoi(buf);
  v1 = *MK_FP(__GS__, 20) ^ cookie;
```

一处是 get_userinput_number_vul 函数里面，一处是main 函数里面

```C
  else
          {
            _printf_chk(v9);
            gets(s);
```

但是程序开启了 canary 栈保护。但是很不幸的是 main 函数中的溢出可以直接覆盖其他的局部变量

```C
unsigned int len; // [esp+0h] [ebp-88h]@1
char s[100]; // [esp+4h] [ebp-84h]@1
char *s_dup; // [esp+68h] [ebp-20h]@1 可以被覆盖
int cookie;
```

s_dup这个变量会作为参数传递到计算 crc 的函数里面，如果覆盖了这个变量，就能 leak 任意地址了。我们可以先计算\x00-\xff这256个值所对应的 crc value，然后建立一个字典，然后用这个函数计算出某一个地址的一个字节的 crc 值，然后就可以知道这个地址的这一个字节是什么了。

```C
len = get_userinput_number_vul();
          size = (int)&len;
          if ( len > 99 )
```

而且bss 段有一个 size 变量指向了栈上的 len 变量，就可以 leak stack address，然后 leak cookie，leak libc。由于远程的 libc 不知道，所以可以通过多 leak 几个 libc 函数的地址，然后通过 libc database 来查找，还真找到了。 leak 完之后就在栈上简单的布置一下 rop，执行 system("/bin/sh")就行了。

# 坑点

1. 建立 crc 查询表的时候，忽视了程序调用的是 gets 函数这个特点，导致发送过去'\x0a'， 以为获得的值是正确的，实际上 gets 函数把'\x0a'这个地方修改成了'\x00'， 然后出现了各种奇怪的问题，leak cookie 的时候最低一位字节就变成了'\x0a', 然后就一直卡在那里。还好 himyth 学长提醒说最新的系统里面最后一位是'\x00'， 我才回过头去调试观察 canary 的值，发现果然最后一位是'\x00'

# 收获

1. 本地利用不成功的时候最好不要先想着远程利用。先在本地测试通过了再说，否则很容易陷入误区。
2. 写好脚本，要用 gdb 调试一下脚本的输出到底正不正确，不能想当然。比如一开始 crc_table 还漏了一个值，用 dynELF 的时候报错，才发现是漏了'\x0a'。
3. 之后再去试试用 dynELF 能否远程 leak libc 地址，不用 libc database。

