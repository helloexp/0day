# PHP Laravel 8.70.1 跨站脚本攻击（XSS）

> poc 可绕过Laravel 的图像上传

## 利用步骤
1. 利用16进制编辑器（01editor），添加  `FF D8 FF E0` 到文件开头
2. 将poc 保存为html ，上传