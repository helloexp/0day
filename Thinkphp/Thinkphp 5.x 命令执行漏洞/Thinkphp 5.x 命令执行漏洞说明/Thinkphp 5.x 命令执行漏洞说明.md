Thinkphp 5.x 命令执行漏洞说明
=============================

**先简单说明一下吧，5.x我们这里罗列了目前碰到的全部tp系列的对应版本漏洞，我在这里简要说明一下，不看别后悔**

> tp框架系列中，5.0.x 跟 5.1.x 中，各个系列里的poc是几乎为通用的
>
> 比如
> 5.0.1中某个poc在5.0.3中也是可以用的，也就是说当我们碰到5.0.8的时候，可以尝试用5.0.1
> 或 5.0.5等 5.0.x 系列的poc去尝试使用，
>
> 5.1.x 系列同理

执行流程：
----------

首先发起请求-\>开始路由检测-\>获取pathinfo信息-\>路由匹配-\>开始路由解析-\>获得模块、控制器、操作方法调度信息-\>开始路由调度-\>解析模块和类名-\>组建命名空间\>查找并加载类-\>实例化控制器并调用操作方法-\>构建响应对象-\>响应输出-\>日志保存-\>程序运行结束

漏洞原因：
----------

路由控制不严谨，默认不开启强制路由，从而可以任意调用Thinkphp的类库

主要有俩种方法，**1.Request中的变量覆盖导致RCE
2.路由控制不严谨导致的RCE**

Request中的变量覆盖导致RCE
--------------------------

版本名 是否可被攻击 攻击条件5.0.0 否 无5.0.1 否 无5.0.2 否 无5.0.3 否 无5.0.4 否 无5.0.5 否 无5.0.6 否 无5.0.7 否 无5.0.8 是 无需开启debug5.0.9 是 无需开启debug5.0.10 是 无需开启debug5.0.11 是 无需开启debug5.0.12 是 无需开启debug5.0.13 是 需开启debug5.0.14 是 需开启debug5.0.15 是 需开启debug5.0.16 是 需开启debug5.0.17 是 需开启debug5.0.18 是 需开启debug5.0.19 是 需开启debug5.0.20 否 无5.0.21 是 需开启debug5.0.22 是 需开启debug5.0.23 是 需开启debug

路由控制不严谨导致的RCE
-----------------------

> 5.0.23\--5.1.31版本

补充
----

> 由于受windows系统的影响，会导致部分payload在windows主机无法使用
>
> 并且由于windows自动加载类加载不到想要的类文件，所以能够下手的就是在框架加载的时候已经加载的类。

**5.1是下面这些：**

    think\Loader 
    Composer\Autoload\ComposerStaticInit289837ff5d5ea8a00f5cc97a07c04561
    think\Error 
    think\Container
    think\App 
    think\Env 
    think\Config 
    think\Hook 
    think\Facade
    think\facade\Env
    env
    think\Db
    think\Lang 
    think\Request 
    think\Log 
    think\log\driver\File
    think\facade\Route
    route
    think\Route 
    think\route\Rule
    think\route\RuleGroup
    think\route\Domain
    think\route\RuleItem
    think\route\RuleName
    think\route\Dispatch
    think\route\dispatch\Url
    think\route\dispatch\Module
    think\Middleware
    think\Cookie
    think\View
    think\view\driver\Think
    think\Template
    think\template\driver\File
    think\Session
    think\Debug
    think\Cache
    think\cache\Driver
    think\cache\driver\File

**5.0 的有：**

    think\Route
    think\Config
    think\Error
    think\App
    think\Request
    think\Hook
    think\Env
    think\Lang
    think\Log
    think\Loader

**两个版本公有的是：**

    think\Route 
    think\Loader 
    think\Error 
    think\App 
    think\Env 
    think\Config 
    think\Hook 
    think\Lang 
    think\Request 
    think\Log

本想找出两个版本共有的利用类和方法，但由于类文件大多被重写了，所以没耐住性子一一去找（菜）

所以，payload为上述类的利用方法，是可以兼容windows和linux多个平台的，兼容多个平台有什么用呢？插件批量可以减少误判等，一条payload通用，一把梭多好。
