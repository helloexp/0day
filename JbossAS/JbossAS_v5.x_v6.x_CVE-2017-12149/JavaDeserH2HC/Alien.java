import java.io.IOException;

/**
 * Classe serializável (implementa serializable) usada no primeiro exemplo
 * para destacar os magic methods readObject (invocado automaticamente durante
 * a desserializacao de objetos deste tipo) e writeObject (invocado durante a
 * serializacao)
 *
 * -----------------------------------------------------------------------
 * Mais detalhes na 12a edição da H2HC (hackers to hackers) magazine:
 * https://www.h2hc.com.br/revista/
 * -----------------------------------------------------------------------
 *
 * @author @joaomatosf
 */
class Alien implements java.io.Serializable {

    String name;
    String source;

    // magic method invocado automaticamente durante a desserializacao
    // de objetos deste tipo
    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        System.out.println("Deserializing an object of class: "+ getClass().getName());
    }

    // magic method invocado automaticamente durante a serializacao
    // de objetos deste tipo
    private void writeObject(java.io.ObjectOutputStream out)
            throws IOException {
        out.defaultWriteObject();
        System.out.println("Serializing an object of class: "+ getClass().getName());
    }
}
