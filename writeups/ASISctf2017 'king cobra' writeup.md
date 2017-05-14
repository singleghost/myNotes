# ASISctf2017 'king cobra' writeup

这道题其实跟逆向啥关系都没有，一开始我还在逆向那个二进制文件，后来发现这个程序只是加载了 python 库。程序一开始会读取环境变量_MEIPASS2， 这个环境变量是一个路径。

```shell
➜  king_cobra export _MEIPASS2=/
➜  king_cobra ./king_cobra
Error loading Python lib '/libpython2.7.so.1.0': /libpython2.7.so.1.0: cannot open shared object file: No such file or directory
```

发现报错，说明程序会在这个路径下面寻找自己所依赖的库文件。然后一开始思路跑偏了，把_MEIPASS2设置成libpython2.7所在的路径了，然后程序又报了新的错误。

```shell
➜  king_cobra export _MEIPASS2=/usr/lib/x86_64-linux-gnu/
➜  king_cobra ./king_cobra
Traceback (most recent call last):
  File "PyInstaller/loader/pyiboot01_bootstrap.py", line 25, in <module>
  File "/usr/local/lib/python2.7/dist-packages/PyInstaller/loader/pyimod03_importers.py", line 315, in load_module
    is_pkg, bytecode = self._pyz_archive.extract(real_fullname)
  File "/usr/local/lib/python2.7/dist-packages/PyInstaller/loader/pyimod02_archive.py", line 352, in extract
    obj = zlib.decompress(obj)
zlib.error: Error -3 while decompressing data: incorrect header check
Failed to execute script pyiboot01_bootstrap
```

一直没搞懂这个错误是什么原因，后来发现这个环境变量根本就不需要我们去改他！

```shell
➜  king_cobra export _MEIPASS2=
➜  king_cobra ./king_cobra
Oops, do you know the usage?!
```

正常运行了，因为这个文件是个独立文件，所以是不需要设置库文件的路径的，库文件都被压缩了然后附在 elf 可执行文件的后面了。如果 pyinstaller 打包的是一个文件夹，那可能需要设置路径（如果库文件被移动到了别的地方的话）。

```shell
➜  king_cobra binwalk king_cobra

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB executable, AMD x86-64, version 1 (SYSV)
29849         0x7499          Zlib compressed data, best compression
30007         0x7537          Zlib compressed data, best compression
30178         0x75E2          Zlib compressed data, best compression
31317         0x7A55          Zlib compressed data, best compression
35518         0x8ABE          Zlib compressed data, best compression
41527         0xA237          Zlib compressed data, best compression
43099         0xA85B          Zlib compressed data, best compression
43567         0xAA2F          Zlib compressed data, best compression
62607         0xF48F          Zlib compressed data, best compression
164151        0x28137         Zlib compressed data, best compression
199259        0x30A5B         Zlib compressed data, best compression
210741        0x33735         Zlib compressed data, best compression
305206        0x4A836         Zlib compressed data, best compression
383435        0x5D9CB         Zlib compressed data, best compression
446410        0x6CFCA         Zlib compressed data, best compression
458316        0x6FE4C         Zlib compressed data, best compression
475699        0x74233         Zlib compressed data, best compression
495146        0x78E2A         Zlib compressed data, best compression
524700        0x8019C         Zlib compressed data, best compression
1551215       0x17AB6F        Zlib compressed data, best compression
2927379       0x2CAB13        Zlib compressed data, best compression
3046504       0x2E7C68        Zlib compressed data, best compression
3109609       0x2F72E9        Zlib compressed data, best compression
3164604       0x3049BC        Zlib compressed data, best compression
3174692       0x307124        Zlib compressed data, best compression
3179036       0x30821C        Zlib compressed data, best compression
3186039       0x309D77        Zlib compressed data, best compression
```



```shell
➜  king_cobra ./king_cobra
Oops, do you know the usage?!
➜  king_cobra ./king_cobra 21321
huh?!, what do you mean by this arg?
➜  king_cobra ./king_cobra reverse_1.1.pyc
your encoded file is ready :P
```

这个程序接收一个文件名作为参数，然后把这个文件加密。后来发现这个程序是用pyinstaller生成的一个 standalone 的打包文件，里面打包集成了很多.so 文件和 python 库。然后一直在网上找怎么解包 pyinstaller 生成的打包文件，一直只找到 windows 版本的，后来发现 pyinstaller 自带了解包程序pyi-archive_viewer

```shell
➜  king_cobra pyi-archive_viewer king_cobra
 pos, length, uncompressed, iscompressed, type, name
[(0, 158, 185, 1, 'm', u'pyimod00_crypto_key'),
 (158, 171, 237, 1, 'm', u'struct'),
 (329, 1139, 2543, 1, 'm', u'pyimod01_os_path'),
 (1468, 4201, 11252, 1, 'm', u'pyimod02_archive'),
 (5669, 6009, 18151, 1, 'm', u'pyimod03_importers'),
 (11678, 1572, 4254, 1, 's', u'pyiboot01_bootstrap'),
 (13250, 468, 726, 1, 's', u'reverse_1.1'),
 (13718, 19040, 35880, 1, 'b', u'Crypto.Cipher._AES.so'),
 (32758, 101544, 149776, 1, 'b', u'_codecs_cn.so'),
 (134302, 35108, 157968, 1, 'b', u'_codecs_hk.so'),
 (169410, 11482, 30992, 1, 'b', u'_codecs_iso2022.so'),
 (180892, 94465, 264464, 1, 'b', u'_codecs_jp.so'),
 (275357, 78229, 137488, 1, 'b', u'_codecs_kr.so'),
 (353586, 62975, 108816, 1, 'b', u'_codecs_tw.so'),
 (416561, 11906, 29384, 1, 'b', u'_hashlib.so'),
 (428467, 17383, 43256, 1, 'b', u'_multibytecodec.so'),
 (445850, 19447, 46824, 1, 'b', u'bz2.so'),
 (465297, 29554, 66800, 1, 'b', u'libbz2.so.1.0'),
 (494851, 1026515, 2361856, 1, 'b', u'libcrypto.so.1.0.0'),
 (1521366, 1376164, 3582904, 1, 'b', u'libpython2.7.so.1.0'),
 (2897530, 119125, 282392, 1, 'b', u'libreadline.so.6'),
 (3016655, 63105, 167240, 1, 'b', u'libtinfo.so.5'),
 (3079760, 54995, 104824, 1, 'b', u'libz.so.1'),
 (3134755, 10088, 31328, 1, 'b', u'readline.so'),
 (3144843, 4344, 11200, 1, 'b', u'resource.so'),
 (3149187, 7003, 7265, 1, 'x', u'flag.enc'), //flag!!!
 (3156190, 6812, 18092, 1, 'x', u'gpl-2.0.txt'),
 (3163002, 647390, 647390, 0, 'z', u'out00-PYZ.pyz')]
?
```

可以看到里面有 flag.enc 文件，把它 extract 出来，发现是一个貌似加密过的 data 文件。然后./king_cobra flag.enc， 发现文件的修改日期改变了，

```shell
➜  king_cobra file flag.enc
flag.enc: PNG image data, 1404 x 74, 8-bit colormap, non-interlaced
```

把后缀改成 png，然后打开就得到 flag 了~

# 收获

1. 了解了 pyinstaller 的好多知识
2. python-uncompyle6-master这个软件可以 decompile pyc 文件https://github.com/rocky/python-uncompyle6