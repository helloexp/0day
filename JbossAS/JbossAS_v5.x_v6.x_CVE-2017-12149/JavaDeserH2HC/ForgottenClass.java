import java.io.IOException;
import java.io.Serializable;
import java.util.Map;

/**
 * Um dos gadgets usados no exemplo didático que demonstra como desviar o
 * fluxo de execucão durante a desserialização (utilizando Dynamic Proxy).
 * Esse gatget invoca um método de um campo (map.entrySet()) e, por isso,
 * pode ser usado como trampolim para o método invoke() de classes que implementem
 * InvocationHandler. No exemplo da revista, o fluxo será desviado para a classe
 * SomeInvocationHandler, que contém um código que se deseja alcançar.
 *
 * -----------------------------------------------------------------------
 * Mais detalhes na 12a edição da H2HC (hackers to hackers) magazine:
 * https://www.h2hc.com.br/revista/
 * -----------------------------------------------------------------------
 *
 * @author @joaomatosf
 */
public class ForgottenClass implements Serializable {

    private Map map;

    // magic method executado automaticamente durante a desserializacao
    // de objetos deste tipo. Repare que é acessado um método de um camop
    // controlado pelos usuários (map.entrySet())
    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException{
        in.defaultReadObject();
        System.out.println("-------------------------------------------");
        System.out.println("The flow is in ForgottenClass.readObject()");
        map.entrySet();
    }

    // outro magic method invocado automaticamente durante a desserialização
    private Object readResolve(){
        System.out.println("-------------------------------------------");
        System.out.println("The flow is in the ForgottenClass.readResolve()");
        return null;
    }

    // método qualquer, que não é invocado durante a desserialização.
    private void anotherMethod(){
        System.out.println("The flow is in ForgottenClass.anotherMethod()");
    }
}