# 记一次被 pwntools 的 recvuntil 坑到的经历

recvuntil 这个函数尽量少用！recvuntil 这个函数尽量少用！recvuntil 这个函数尽量少用！用的时候最好加上 timeout！重要的事情说三遍。

 pipe 缓冲区是4096个字节，如果调用 recvuntil 函数又不加上 timeout 的时候，如果 pipe 缓冲区被填满，而缓冲区里面没有对应的字符串出现，这时候 recvuntil 就会阻塞，而新的内容又进不了缓冲区，而新的内容里很可能有对应的字符串！导致运行 exp 的时候容易出现莫名其妙阻塞的情况。

所以我们可以用 recvrepeat 之类的函数替代 recvuntil 和 sendlineafter，或者一定要加上 timeout 才行。

还有 fuzz 的时候，在 while 循环里面最好加上 sleep(0.1), 不加也没什么问题，少占用资源嘛。自己用 pwntools 手写 fuzz 的时候，fuzz 程序最后都会被 OS killed 掉，用 dmesg 查看 log 发现是 OOM（out of memory） 的问题。

