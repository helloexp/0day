天融信dlp+未授权+越权

管理员登录系统之后修改密码，未采用原密码校验，且存在未授权访问导致存在越权修改管理员密码。

 默认用户superman的uid=1

POST /?module-auth_user&action=mod_edit.pwd HTTP/1.1