import java.io.Serializable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

/**
 * Um dos gadgets usados no exemplo didático que demonstra como desviar o
 * fluxo de execucão durante a desserialização (utilizando Dynamic Proxy).
 * O método invoke() desta classe é alcançado quando o readObject da classe
 * ForgottenClass invoca um método em um campo controlado pelo usuário (map.entrySet())
 * O campo irá conter um Proxy entre a interface Map e este InvocationHandler.
 *
 * -----------------------------------------------------------------------
 * Mais detalhes na 12a edição da H2HC (hackers to hackers) magazine:
 * https://www.h2hc.com.br/revista/
 * -----------------------------------------------------------------------
 *
 *
 * @author @joaomatosf
 */
public class SomeInvocationHandler implements InvocationHandler, Serializable {

    private String cmd;

    // metodo invoke não é um magic method (ou seja, *não* é invocado automaticamente
    // durante a desserialização. Porém, pode ser alcançado por meio de um Dynamic Proxy.
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        System.out.println("-------------------------------------------");
        System.out.println("Invoke method reached! This method can do something dangerous!");
        Runtime.getRuntime().exec(cmd);
        return null;
    }

    // magic method invocado automaticamente durante a desserialização de objetos
    // deste tipo
    private void readObject(java.io.ObjectInputStream s)
            throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();
        System.out.println("-------------------------------------------");
        System.out.println("The flow is in SomeInvocationHandler.readObject()");
    }
}