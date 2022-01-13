import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
/**
 * Exemplo simples que demonstra a serializacao nativa de um objeto
 * e o salva em um arquivo. Observe que, durante a serializacao, o método
 * writeObject da classe Alien (que é o tipo do Objeto sendo serializado)
 * é automaticamente invocado.
 *
 * -----------------------------------------------------------------------
 * Mais detalhes na 12a edição da H2HC (hackers to hackers) magazine:
 * https://www.h2hc.com.br/revista/
 * -----------------------------------------------------------------------
 *
 * **** USAGE ****
 *
 * Compilando:
 * $ javac TestSerialize.java
 *
 * Executando
 * $ java TestSerialize
 *
 * @author @joaomatosf
 */
public class TestSerialize {

    public static void main(String[] args)
            throws IOException {

        // Instancia objeto a ser serializado e atribui
        // valores aos seus campos "name" e "source"
        Alien ET = new Alien();
        ET.name = "Abu ce taí";
        ET.source = "Andromeda Galaxy";

        // Cria FileOutputStream para armazenar o objeto serializado em um arquivo
        FileOutputStream fos = new FileOutputStream("ET_object.ser");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(ET); // <-- Realiza a serializacao
        oos.flush();
        oos.close();

    }
}
