# How to install **woboq_codebrowser** on Mac OS and Linux

woboq_codebrowser是一个很不错的源代码阅读工具

### 通过源代码安装

```shell
git clone https://github.com/woboq/woboq_codebrowser
```

## 在 Linux 上编译

#### dependency

```shell
sudo apt-get install clang #需要安装3.4版本及以后的 clang
sudo apt-get install llvm
sudo apt-get install libclang-3.8-dev #这个项目依赖于一些 clang 的库
sudo apt-get install zlib1g-dev #安装一个用于压缩的库，否则 ld 的时候会报错，missing -lz
```

### 编译

```
cmake . -DLLVM_CONFIG_EXECUTABLE=/path/to/llvm-config-<version_num> -DCMAKE_BUILD_TYPE=Release && make -j8
```

### 安装

```
cp ./generator/codebrowser_generator /usr/local/bin
cp ./indexgenerator/codebrowser_indexgenerator /usr/local/bin
```



## 在 Mac 上编译

App store安装XCode

安装xcode command line tools

```
xcode-select --install
```

安装 clang库

```
brew install llvm --with-clang --rtti
```

编译
```
cmake . -DLLVM_CONFIG_EXECUTABLE=/usr/local/Cellar/llvm/<your_llvm_version>/bin/llvm-config -DCMAKE_BUILD_TYPE=Release
make
```



## 在 Mac 上使用 generator

[官方教程](https://github.com/woboq/woboq_codebrowser) 讲的比较详细，但是适用于 Linux，如果在 Mac 上的非 Cmake 项目，还需要修改`scripts/fake_compiler.sh`（这里被坑的好惨）

修改后的fake_compiler.sh

```shell
#! /bin/sh

#
# This script can be used to generate the compile_commands.json file.
# Configure this script as the compiler, e.g. with the CC/CXX environment variables.
# Export the $COMPILATION_COMMANDS environement variable to the full path of the compile_commands.json file.
# set $FORWARD_COMPILER to the path of the actual compiler to perform the actual compilation.
#
# Example using configure (similar when using qmake):
#
# export COMPILATION_COMMANDS=/path/to/compile_commands.json
# export FORWARD_COMPILER=g++
# CC=/path/to/fake_compiler.sh CXX=/path/to/fake_compiler.sh ./configure
# echo "[" > $COMPILATION_COMMANDS
# make -j1
# echo " { \"directory\": \".\", \"command\": \"true\", \"file\": \"/dev/null\" } ]" >> $COMPILATION_COMMANDS


directory=$PWD
args=$@
file=`echo $args | sed 's/.* \([^ ]*\)/\1/'`

# if you are using mac os, use `brew install coreutils` to install greadlink, then change the readlink command to greadlink

#下面四行是被修改过后的
if [[ "$OSTYPE" == "darwin"* ]]; then
	new_file=`cd $directory && greadlink -f $file 2>/dev/null | xargs echo -n`	#如果是苹果系统，需要使用 greadlink，而不是 readlink, Mac OS 上的 readlink 和 linux 上的 readlink 是两个不同的程序
else
	new_file=`cd $directory && readlink -f $file 2>/dev/null | xargs echo -n`
fi
args=`echo $args | sed "s, -I\.\./, -I$directory/../,g" | sed "s, -I\. , -I$directory ,g" | sed "s, -I\./, -I$directory,g" | sed "s, -I\(/]\), -I$directory/\1,g" | sed 's,\\\\,\\\\\\\\,g' | sed 's/"/\\\\"/g'`
echo "{ \"directory\": \"$directory\", \"command\": \"c++ $args\", \"file\": \"$new_file\" } , " >> $COMPILATION_COMMANDS

if [ -z $FORWARD_COMPILER ]; then
    true
else
    $FORWARD_COMPILER "$@"
fi

```

由于 Mac OS 上 readlink 没有 -f选项，关键是 Mac OS 上的 readlink 和 Linux 上的 readlink 根本就不一样！所以我第一次尝试的时候发现生成的compile_commands.json这个文件中的 file 字段全都是空的。

解决办法是先`brew install coreutils`， 这个带有greadlink程序，和 Linux 上的 readlink 程序功能一样，然后使用上面修改后的脚本就行了。