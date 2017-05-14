# django和 pyspider 的部署心得

B/S大作业需要开发一个新闻聚合的网站。我想用 django 作为后端， 选择pyspider作为爬虫框架。在 pyspider 上测试了三个网站了之后，想让 pyspider 的结果存入 mysql 数据库中，但是不想直接用 python 的 mysql 模块将结果写入，想让 pyspider 使用 django 的 model 类。django 的 model 类是对底层数据库的一个封装，使用 model 类就不用裸写 sql 语句了，而且可以根据需要在任意时候更换使用的数据库。

但是不幸的是 pyspider 是使用 python2安装的，django 是在virtual-env下使用 python3安装的，virtual-env的名字是rss_site。我先切换到 rss_site这个 virtual-env，然后安装 pyspider，然后为了方便直接把原来 pyspider 运行目录下的 data 文件夹（里面有result.db、task.db等文件）copy 到新的运行目录下，然后跑 pyspider，但是 pyspider 的打印的 log 信息中显示restart_task之后只调用了on_start方法，然后就结束了。把 data 文件夹删掉，重新运行 pyspider 就正常了，可能与自己一会在 python2环境下运行 pyspider，一会又跑到virtual-env(python3的环境下)运行 pyspider 有关，具体是什么原因搞不太清了。

在 django project 的 mysite 目录下面建立文件config.json

```json
{
	"result_worker": {
		"result-cls": "my_result_worker.MyResultWorker"
	}
}
```

指定 result_worker 为自己定义的类MyResultWorker，该类在 pyspider 的运行目录下的my_result_worker.py文件中定义。

```python
from pyspider.result import ResultWorker

#下面这四行是关键
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'mysite.settings'
import django
django.setup()

from showNews.models import News
import logging

class MyResultWorker(ResultWorker):
    def on_result(self, task, result):
        assert task['taskid']
        assert task['project']
        assert task['url']
        assert result
        logging.info("This is my result worker")
        n = News(title=result['title'], publish_time=result['publish_time'], body=result['body'], source_url=result['url'], source=result['source'], category=result['category'])
        n.save()
        logging.info("save the result into database")
        

```

在编写这个文件 的时候，遇到了一些问题，由于需要 import 在 django project 中定义的 News 类，所以如果没有导入一下 django 的必要的设置，就会报错。一开始是报了这个错误

```shell
django.core.exceptions.ImproperlyConfigured: Requested setting DATABASES,   but settings are not configured. You must either define the environment   variable DJANGO_SETTINGS_MODULE or call settings.configure()   before accessing settings.

```

解决这个问题可以选择在 shell 中 export=DJANGO_SETTINGS_MODULE='mysite.settings', 其中 mysite 是 django project 的 name。或者在 python 脚本的一开始设置环境变量。

但是设置了环境变量之后又出现新的问题，

```
django.core.exceptions.AppRegistryNotReady: Models aren't loaded yet.
```

所以还需要加上这两行

```python
import django
django.setup()
```

然后就可以在命令行运行

```shell
pyspider -c config.json all
```

大功告成了！

之前还尝试写了个脚本来启动pyspider的各个组件，后来发现没必要，还是用 config.json最方便

```bash
#!/bin/bash

# start **only one** scheduler instance
nohup pyspider scheduler &

# phantomjs
nohup pyspider phantomjs &

# start fetcher / processor / result_worker instances as many as your needs
nohup pyspider --phantomjs-proxy="localhost:25555" fetcher &
nohup pyspider processor &
nohup pyspider result_worker --result-cls=my_result_worker.MyResultWorker &

# start webui, set `--scheduler-rpc` if scheduler is not running on the same host as webui
nohup pyspider webui &

```

