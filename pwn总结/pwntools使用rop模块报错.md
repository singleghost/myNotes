# pwntools使用rop模块报错

```python
In [3]: elf=  ELF("./alloca")
[*] '/media/psf/Home/workspace/CTF/pwnable/alloca/alloca'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE

In [4]: rop = ROP(elf)
---------------------------------------------------------------------------
ImportError                               Traceback (most recent call last)
<ipython-input-4-b73050b43606> in <module>()
----> 1 rop = ROP(elf)

/usr/local/lib/python2.7/dist-packages/pwnlib/rop/rop.pyc in __init__(self, elfs, base, **kwargs)
    397             elfs(list): List of ``pwnlib.elf.ELF`` objects for mining
    398         """
--> 399         import ropgadget
    400 
    401         # Permit singular ROP(elf) vs ROP([elf])

/usr/local/lib/python2.7/dist-packages/ropgadget/__init__.pyc in <module>()
     12 
     13 import ropgadget.args
---> 14 import ropgadget.binary
     15 import ropgadget.core
     16 import ropgadget.gadgets

/usr/local/lib/python2.7/dist-packages/ropgadget/binary.py in <module>()
     11 ##  (at your option) any later version.
     12 
---> 13 from ropgadget.loaders.elf       import *
     14 from ropgadget.loaders.pe        import *
     15 from ropgadget.loaders.raw       import *

/usr/local/lib/python2.7/dist-packages/ropgadget/loaders/__init__.py in <module>()
     11 ##  (at your option) any later version.
     12 
---> 13 import ropgadget.loaders.elf
     14 import ropgadget.loaders.macho
     15 import ropgadget.loaders.pe

/usr/local/lib/python2.7/dist-packages/ropgadget/loaders/elf.py in <module>()
     11 ##  (at your option) any later version.
     12 
---> 13 from capstone   import *
     14 from ctypes     import *
     15 from struct     import unpack

/usr/local/lib/python2.7/dist-packages/capstone/__init__.py in <module>()
    228             pass
    229     if _found == False:
--> 230         raise ImportError("ERROR: fail to load the dynamic library.")
    231 
    232 

ImportError: ERROR: fail to load the dynamic library.

```

查看capstone目录下缺少了libcapstone.so文件，後來找到有人在 capstone 的 Github 開了 [issue](https://github.com/aquynh/capstone/issues/413) 。 



```shell
cp /usr/local/lib/python2.7/dist-packages/usr/lib/python2.7/dist-packages/capstone/libcapstone.so /usr/local/lib/python2.7/dist-packages/capsto
ne/.
```

像上面这样把libcapstone.so拷贝过去就行了。



但是解决了这个错误，又出现了新的错误。

```python
In [7]: rop = ROP(elf)
---------------------------------------------------------------------------
ImportError                               Traceback (most recent call last)
<ipython-input-7-b73050b43606> in <module>()
----> 1 rop = ROP(elf)

/usr/local/lib/python2.7/dist-packages/pwnlib/rop/rop.pyc in __init__(self, elfs, base, **kwargs)
    397             elfs(list): List of ``pwnlib.elf.ELF`` objects for mining
    398         """
--> 399         import ropgadget
    400 
    401         # Permit singular ROP(elf) vs ROP([elf])

/usr/local/lib/python2.7/dist-packages/ropgadget/__init__.pyc in <module>()
     12 
     13 import ropgadget.args
---> 14 import ropgadget.binary
     15 import ropgadget.core
     16 import ropgadget.gadgets

/usr/local/lib/python2.7/dist-packages/ropgadget/binary.py in <module>()
     11 ##  (at your option) any later version.
     12 
---> 13 from ropgadget.loaders.elf       import *
     14 from ropgadget.loaders.pe        import *
     15 from ropgadget.loaders.raw       import *

/usr/local/lib/python2.7/dist-packages/ropgadget/loaders/__init__.py in <module>()
     11 ##  (at your option) any later version.
     12 
---> 13 import ropgadget.loaders.elf
     14 import ropgadget.loaders.macho
     15 import ropgadget.loaders.pe

/usr/local/lib/python2.7/dist-packages/ropgadget/loaders/elf.py in <module>()
     11 ##  (at your option) any later version.
     12 
---> 13 from capstone   import *
     14 from ctypes     import *
     15 from struct     import unpack

/usr/local/lib/python2.7/dist-packages/capstone/__init__.py in <module>()
      4 if _python2:
      5     range = xrange
----> 6 from . import arm, arm64, mips, ppc, sparc, systemz, x86, xcore
      7 
      8 __all__ = [

ImportError: cannot import name arm

```



网上转了一圈没有找到解决办法，病急乱投医只好尝试一下下面的方法

```shell
sudo apt-get install python-capstone
```



居然成功了，不再报错！

虽然后面在使用rop模块的时候还是遇到了点问题，留待以后解决吧。。。



