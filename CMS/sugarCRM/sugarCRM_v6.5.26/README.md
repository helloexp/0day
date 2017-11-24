## 漏洞详情
    * SQL注入漏洞->modules/Emails/DetailView.php $query语句->$parent_id 中加入 \ 可绕过防护措施                  *
    * CSRF+盲注                                 
    * 对象注入                                                
    * 认证文件泄露(任意文件读取)->modules/Connecors/controller.php->action_CallRest()函数->/index.php?...&module=CallRest&url=/etc/passwd 可读取配置文件                            
## 利用条件 :                      
    1 3 4 只能通过一个有效的用户会话进行访问并利用 2 则可以直接利用
