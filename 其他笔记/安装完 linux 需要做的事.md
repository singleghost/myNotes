# 安装完 linux 需要做的事

1、更换apt源

阿里云的源

```c
# deb cdrom:[Ubuntu 16.04 LTS Xenial Xerus - Release amd64 (20160420.1)]/ xenial main restricted

deb-src http://archive.ubuntu.com/ubuntu xenial main restricted #Added by software-properties

deb http://mirrors.aliyun.com/ubuntu/ xenial main restricted

deb-src http://mirrors.aliyun.com/ubuntu/ xenial main restricted multiverse universe #Added by software-properties

deb http://mirrors.aliyun.com/ubuntu/ xenial-updates main restricted

deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates main restricted multiverse universe #Added by software-properties

deb http://mirrors.aliyun.com/ubuntu/ xenial universe

deb http://mirrors.aliyun.com/ubuntu/ xenial-updates universe

deb http://mirrors.aliyun.com/ubuntu/ xenial multiverse

deb http://mirrors.aliyun.com/ubuntu/ xenial-updates multiverse

deb http://mirrors.aliyun.com/ubuntu/ xenial-backports main restricted universe multiverse

deb-src http://mirrors.aliyun.com/ubuntu/ xenial-backports main restricted universe multiverse #Added by software-properties

deb http://archive.canonical.com/ubuntu xenial partner

deb-src http://archive.canonical.com/ubuntu xenial partner

deb http://mirrors.aliyun.com/ubuntu/ xenial-security main restricted

deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security main restricted multiverse universe #Added by software-properties

deb http://mirrors.aliyun.com/ubuntu/ xenial-security universe

deb http://mirrors.aliyun.com/ubuntu/ xenial-security multiverse

```





2、 

```shell
sudo apt-get update
```



3、

```shell
sudo apt-get install vim
sudo apt-get install python-pip
```



4、 更改pip源

有的朋友要改pypi源 mac没有.pip文件夹很正常 因为要自己建

在终端进入目录：cd ~/

如果没有 .pip 文件夹，那么就要新建这个文件夹，mkdir .pip

然后在.pip 文件夹内新建一个文件 touch pip.conf，

编辑 pip.conf 文件，写入阿里云

```
[global]

index-url = http://mirrors.aliyun.com/pypi/simple/

[install]

trusted-host=mirrors.aliyun.com

```



6、

```shell
pip install —upgrade pip
sudo apt-get install libssl-dev openssl 
sudo apt-get install python git
```



7、

```shell
sudo pip install pwntools
```



8、配置ssh

ssh配置authorized_keys后仍然需要输入密码的问题

注意$HOME/.ssh目录 或 $HOME目录的权限 最好是700。

注意authorized_keys的权限  chmod 644 authorized_keys。

```shell
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
echo "DONE! debug your program with gdb and enjoy”
```



最后给出完整的自动配置 shell 脚本

```bash
# !/usr/bin/env bash

sudo mv /etc/apt/sources.list /etc/apt/sources.list.backup

sudo bash -c 'echo -e "deb-src http://archive.ubuntu.com/ubuntu xenial main restricted #added by software-properties\ndeb http://mirrors.aliyun.com/ubuntu/ xenial main restricted\ndeb-src http://mirrors.aliyun.com/ubuntu/ xenial main restricted multiverse universe #added by software-properties\ndeb http://mirrors.aliyun.com/ubuntu/ xenial-updates main restricted\ndeb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates main restricted multiverse universe #added by software-properties\ndeb http://mirrors.aliyun.com/ubuntu/ xenial universe\ndeb http://mirrors.aliyun.com/ubuntu/ xenial-updates universe\ndeb http://mirrors.aliyun.com/ubuntu/ xenial multiverse\ndeb http://mirrors.aliyun.com/ubuntu/ xenial-updates multiverse\ndeb http://mirrors.aliyun.com/ubuntu/ xenial-backports main restricted universe multiverse\ndeb-src http://mirrors.aliyun.com/ubuntu/ xenial-backports main restricted universe multiverse #added by software-properties\ndeb http://archive.canonical.com/ubuntu xenial partner\ndeb-src http://archive.canonical.com/ubuntu xenial partner\ndeb http://mirrors.aliyun.com/ubuntu/ xenial-security main restricted\ndeb-src http://mirrors.aliyun.com/ubuntu/ xenial-security main restricted multiverse universe #added by software-properties\ndeb http://mirrors.aliyun.com/ubuntu/ xenial-security universe\ndeb http://mirrors.aliyun.com/ubuntu/ xenial-security multiverse" > /etc/apt/sources.list' && sudo apt-get update

sudo apt-get install vim python-pip libssl-dev openssl git ipython

---

#change pip source

cd

mkdir .pip

cd .pip

echo -e "[global]\n\nindex-url = http://mirrors.aliyun.com/pypi/simple/\n[install]\n\ntrusted-host=mirrors.aliyun.com" > pip.conf

pip install --upgrade pip

sudo pip install pwntools

---

#setup gdb plugin --peda

cd

git clone https://github.com/longld/peda.git ~/peda

echo "source ~/peda/peda.py" >> ~/.gdbinit

echo "done! debug your program with gdb and enjoy”

```

