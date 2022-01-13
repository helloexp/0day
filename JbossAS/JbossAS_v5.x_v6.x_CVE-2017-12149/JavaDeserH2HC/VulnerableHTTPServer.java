import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.annotation.IncompleteAnnotationException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
//this import is only for java 1.8
//import java.util.Base64;
import java.security.Key;
import java.util.zip.GZIPInputStream;

/**
 * Simples Servidor HTTP que desserializa dados recebidos nos seguintes formatos:
 *
 * 1) via HTTP POST em formato binário (ou seja, \xAC\xED)
 * 2) via HTTP POST como valor de algum parâmetro (eg. "ViewState") nos formatos 1) base64 (rO0...) ou 2) gzip+base64 (H4sI...)
 * 3) via cookies (header cookie) nos formatos base64 (rO0) ou gzip+base64 (H4sI) (eg. Cookie: JSESSIONID=rO0... ou Cookie: JSESSIONID=H4sI...)
 * 4) via Cookie rememberMe (like Apache Shiro), criptografado com aes-128-cbc e chave hardcoded
 * 5) via XML para explorar o XStream
 *
 * Após a desserialização, ele tenta fazer um cast para Integer, a fim de simular o que
 * ocorre em um servidor "real" (erro de casting após a desserialização)
 *
 *
 * OBS: Sobre Apache Shiro, ver:
 * https://github.com/apache/shiro/blob/master/crypto/cipher/src/main/java/org/apache/shiro/crypto/JcaCipherService.java
 * https://github.com/apache/shiro/blob/8acc82ab4775b3af546e3bbde928f299be62dc23/integration-tests/guice3/src/main/webapp/WEB-INF/shiro.ini
 * Para geracao do payload, use CommonsCollections2 ou CommonsCollections4 do ysoserial e criptografe com aes-128-cbc
 * Se preferir, existem mtos sccripts prontos para geracao do payload, veja:
 * ex: https://github.com/leveryd/vulndocker/blob/78ba54edbd2dd81f09bb6d3f03a446555e6b7614/vuln/shiro/shirotest.py
 * Análise: http://www.freebuf.com/articles/system/125187.html
 *
 * -----------------------------------------------------------------------
 * Mais detalhes na 12a edição da H2HC (hackers to hackers) magazine:
 * https://www.h2hc.com.br/revista/
 * -----------------------------------------------------------------------
 *
 * **** USAGE ****
 *
 * Compilando:
 * $ javac VulnerableHTTPServer.java -XDignore.symbol.file
 *
 * Executando
 * $ java VulnerableHTTPServer
 *
 * Ou, caso deseje testar payloads para explorar gadgets de bibliotecas específicas, use o -cp. Exs:
 * $ java -cp .:commons-collections-3.2.1.jar VulnerableHTTPServer
 * $ java -cp .:xstream-1.4.6.jar:commons-collections-3.2.1.jar VulnerableHTTPServer
 *
 * @author @joaomatosf
 */

public class VulnerableHTTPServer {

    public static void banner(){
        System.out.println("* =============================================================== *");
        System.out.println("*    Simple Java HTTP Server for Deserialization Lab v0.01        *");
        System.out.println("*    https://github.com/joaomatosf/JavaDeserH2HC                  *");
        System.out.println("* =============================================================== *");
        System.out.println("You can inject java serialized objects in the following formats:");
        System.out.println(
                "\n 1) Binary in HTTP POST (ie \\xAC\\xED). Ex:\n" +
                "    $ curl 127.0.0.1:8000 --data-binary @ObjectFile.ser\n"+
                "\n 2) Base64 or Gzip+Base64 via HTTP POST parameters. Ex:\n" +
                "    $ curl 127.0.0.1:8000 -d \"ViewState=rO0ABXNy...\"\n"+
                "    $ curl 127.0.0.1:8000 -d \"ViewState=H4sICAeH...\"\n"+
                "\n 3) Base64 or Gzip+Base64 in cookies. Ex:\n"+
                "    $ curl 127.0.0.1:8000 -H \"Cookie: JSESSIONID=rO0ABXNy...\"\n"+
                "    $ curl 127.0.0.1:8000 -H \"Cookie: JSESSIONID=H4sICAeH...\"\n"+
                "\n 4) Base64 of AES-CBC encrypted with hardcoded Apache Shiro key. Ex:\n" +
                "    $ curl 127.0.0.1:8000 -H \"Cookie: rememberMe=MTIzNDU2Nzg...\"\n"+
                "\n 5) XML for XStream RCE vulnerability/serialization. Ex:\n" +
                "    $ curl 127.0.0.1:8000 -d @file.xml\n -H \"Content-Type: application/xml\"");



        System.out.println("OBS: To test gadgets in specific libraries, run with -cp param. Ex:\n" +
                "$ java -cp .:commons-collections-3.2.1.jar VulnerableHTTPServer");
        System.out.println("==================================================================");

    }

    public static void main(String[] args) throws IOException {
        banner();
        int port = 8000;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new HTTPHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
        System.out.println("\nJRE Version: "+System.getProperty("java.version"));
        System.out.println("[INFO]: Listening on port "+port);
        System.out.println();
    }


    static class HTTPHandler implements HttpHandler {

        String aesHardedCodeKey = "kPH+bIxk5D2deZiIxcaaaA==";

        public void handle(HttpExchange t) throws IOException {

            System.out.println("[INFO]: Received "+t.getRequestMethod()+" "+t.getRequestURI()+" from: "+t.getRemoteAddress());

            String responseMsg = null;
            boolean containsCookie = t.getRequestHeaders().containsKey("cookie");

            // if there's a cookie with serialized java object
            if (containsCookie){
                String object = t.getRequestHeaders().get("cookie").get(0);
                object = getObjectValue(object);

                if (object.startsWith("H4sI") || object.startsWith("rO0") )
                    responseMsg = deserialize(object);
                else { // try deserialize aes-cbc encrypted object

                    byte[] plainText = decryptAES(object,aesHardedCodeKey);
                    if (plainText == null)
                        responseMsg = "\nAn error ocurred when decrypting the stream.\n";
                    else
                        responseMsg = deserialize(new ByteArrayInputStream(plainText));
                }

            }
            else if (t.getRequestMethod().equals("POST")){

                InputStream input = t.getRequestBody();
                // take 2 bytes from header to check if it is a raw object
                PushbackInputStream pbis = new PushbackInputStream( input, 2 );
                byte [] header = new byte[2];
                int len = pbis.read(header);
                pbis.unread( header, 0, len );
                StringBuffer headerResult = new StringBuffer();
                for (byte b: header)
                    headerResult.append(String.format("%02x", b));

                // deserialize raw
                if (headerResult.toString().equals("aced"))
                    responseMsg = deserialize(pbis); // deserialize RAW
                else{ // deserialize H4sI, rO0,...
                    // read input into string
                    InputStreamReader isr = new InputStreamReader(pbis, "utf-8");
                    BufferedReader br = new BufferedReader(isr);
                    String body = br.readLine();
                    String paramName = "";
                    String object = getObjectValue(body);

                    if (object.startsWith("H4sI") || object.startsWith("rO0") )
                        responseMsg = deserialize(object); // deserialize H4sI, rO0...
                    else if (object.startsWith("<") )
                        responseMsg = deserializeXStream(object); // xtream
                }


            }// end if POST
            else{

                responseMsg = "<html>" +
                        "\n<title>DeserLab v0.01</title> " +
                        "\n<br>DeserLab v0.01 -  Vulnerable HTTP Server for Deserialization Vulnerabilities Tests." +
                        "\n<br>See examples at: <a href=\"https://github.com/joaomatosf/JavaDeserH2HC\">https://github.com/joaomatosf/JavaDeserH2HC</a>" +
                        "\n<br> <form id=\"0\" name=\"inicial\" method=\"post\" action=\"/post\" enctype=\"application/x-www-form-urlencoded\">" +
                        "\n<bbr> <input type=\"hidden\" name=\"javax.faces.ViewState\" id=\"javax.faces.ViewState\" value=\"H4sI\" />";

            }
            t.getResponseHeaders().add("Server", "Vulnerable Java HTTP Server v0.01");
            t.getResponseHeaders().add("Info", "http://github.com/joaomatosf/JavaDeserH2HC");
            t.getResponseHeaders().add("Content-Type", "x-java-serialized-object");

            if (t.getRequestURI().getPath().contains("jexws") || t.getRequestURI().getPath().contains("jexinv"))
                t.sendResponseHeaders(404, responseMsg.length());
            else
                t.sendResponseHeaders(200, responseMsg.length());

            OutputStream os = t.getResponseBody();
            os.write(responseMsg.getBytes());
            os.close();

        }

        public boolean hasParam(String object){
            if (object.indexOf("=")<40 && object.indexOf("=")>0 && object.split("=")[1].length() > 4)
                return true;
            else
                return false;
        }
        public String getParamName(String object){
            if (hasParam(object))
                return object.substring(0, object.indexOf("=")+1).split("=")[0] + "=";
            else
                return "";
        }
        public String getObjectValue(String object){
            if (hasParam(object)) {
                String paramName = getParamName(object);
                return object.split(paramName)[1];
            }
            else
                return object;

        }


        public String deserialize(String object){

            ObjectInputStream ois = null;
            InputStream is = null;
            GZIPInputStream gis = null;

            // if payload is urlencoded
            if (object.contains("%2B")) {
                try {
                    object = URLDecoder.decode(object, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    return "\nInvalid encoding. You should use URL Encode!\n";
                }
            }

            try {
                byte[] b64DecodedObj = new BASE64Decoder().decodeBuffer(object);
                // This another implementation of Base64 is only for java >= 1.8
                //byte[] b64DecodedObj = Base64.getDecoder().decode(object);
                is = new ByteArrayInputStream(b64DecodedObj);
            }catch (Exception e){
                return "\nInvalid Base64!\n";
            }

            if (object.startsWith("H4sI")) {
                try {
                    gis = new GZIPInputStream(is);
                    ois = new ObjectInputStream(gis);
                } catch (IOException e) {
                   return "\nThe Stream not contains a Java Object!\n";
                }
                catch (Exception e) {
                    return "\nInvalid Gzip stream!\n";
                }
            }
            else {
                try {
                    ois = new ObjectInputStream(is);
                }
                catch (IOException e ){
                    return "\nThe Stream not contains a Java Object!\n";
                }
                catch (Exception e){
                    return e.toString()+"\n";
                }
            }

            // Deserialization
            try{
                int number = (Integer) ois.readObject();
            }
            catch (ClassNotFoundException e) {
                return "\nSerialized class not found in classpath\n";
            }
            catch (IOException e) {
                return e.toString()+"\n";
            }
            catch (ClassCastException e){
                e.printStackTrace();
            } catch (IncompleteAnnotationException e){
                e.printStackTrace();
                System.out.println("\n[INFO] This payload not works in JRE >= 8u72. Try another version such as those\n" +
                        "       which use TiedMapEntry + HashSet (by @matthiaskaiser).\n");
                return "\nThis payload not works in JRE >= 8u72. Try another version such as those which use TiedMapEntry + HashSet (by @matthiaskaiser).\n";
            }
            catch (Exception e){
                e.printStackTrace();
            }


            return "\nData deserialized!\n";
        }

        public String deserialize(InputStream is){

            ObjectInputStream ois = null;

            try{
                ois = new ObjectInputStream(is);
            }catch (EOFException e){
                e.printStackTrace();
                return "\nThe request body not contains a Stream!\n";
            } catch (Exception e) {
                return e.toString()+"\n";
            }

            try {
                // This cast simulate what occurs in a real server
                int number = (Integer) ois.readObject();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                return "\nSerialized class not found in classpath\n";
            } catch (ClassCastException e){
                e.printStackTrace();
            } catch (IncompleteAnnotationException e){
                e.printStackTrace();
                System.out.println("\n[INFO] This payload not works in JRE >= 8u72. Try another version such as those\n" +
                        "       which use TiedMapEntry + HashSet (by @matthiaskaiser).\n");
                return "\nThis payload not works in JRE >= 8u72. Try another version such as those which use TiedMapEntry + HashSet (by @matthiaskaiser).\n";
            }
            catch (Exception e){
                e.printStackTrace();
            }

            return "\nData deserialized!\n";
        }

        public String deserializeXStream(String xml){

            Class classXStream = null;
            Class classDomDriver = null;
            Class classHierarchicalStreamDriver = null;
            //Class classJsonHierarchicalStreamDriver = null;

            try {

                classHierarchicalStreamDriver = Class.forName("com.thoughtworks.xstream.io.HierarchicalStreamDriver");
                //classJsonHierarchicalStreamDriver = Class.forName("com.thoughtworks.xstream.io.json.JsonHierarchicalStreamDriver");
                classXStream = Class.forName("com.thoughtworks.xstream.XStream");
                classDomDriver = Class.forName("com.thoughtworks.xstream.io.xml.DomDriver");

                //Constructor ctrJsonDriver = classJsonHierarchicalStreamDriver.getDeclaredConstructor();
                Constructor ctrDomDriver = classDomDriver.getDeclaredConstructor();
                Constructor ctrXStream = classXStream.getDeclaredConstructor(classHierarchicalStreamDriver);

                Object domDriverInstance = ctrDomDriver.newInstance();
                //Object jsonDriverInstance = ctrJsonDriver.newInstance();
                Object xstreamInstance = ctrXStream.newInstance(domDriverInstance);

                //Desativado json...
                //if (xml.startsWith("<"))
                    //xstreamInstance = ctrXStream.newInstance(domDriverInstance);
                //else
                 //   xstreamInstance = ctrXStream.newInstance(jsonDriverInstance);

                Method m = xstreamInstance.getClass().getMethod("fromXML", String.class);
                m.invoke(xstreamInstance, xml);


            } catch (ClassNotFoundException e) {
                e.printStackTrace();
                return "\nXStream lib not found in classpath. You must add \"xstream-1.4.6.jar\" in -cp param. Ex: \n" +
                        "java -cp .:xstream-1.4.6.jar:commons-collections-3.2.1.jar VulnerableServer\n\n";
            } catch (Exception e){
                e.printStackTrace();
                return "\nError deserializing XML...\n";
            }

            return "\nXML deserialized!\n";
        }

        public byte[] decryptAES(String object, String aesKey){

            byte[] iv = new byte[16];
            String algorithmName = "AES";

            byte[] cipherText = null;
            byte[] plainTextWithIV = null;
            byte[] plainText = null;
            byte[] key = null;

            try {
                // first decode object from base64
                cipherText = new BASE64Decoder().decodeBuffer(object);
                // use the same harded code key from apache shino
                key = new BASE64Decoder().decodeBuffer(aesKey);

            } catch (Exception e) { e.printStackTrace(); return null; }

            try {

                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                Key keySpec = new SecretKeySpec(key, algorithmName);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec,ivSpec);
                // decrypt ciphertext and put the IV in the header
                plainTextWithIV = cipher.doFinal(cipherText);
                // remove the iv from header of plaintext in order to deserialize it later
                plainText = new byte[plainTextWithIV.length - iv.length];
                System.arraycopy(plainTextWithIV, iv.length, plainText, 0, plainText.length);
                return plainText;

            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

    }
}