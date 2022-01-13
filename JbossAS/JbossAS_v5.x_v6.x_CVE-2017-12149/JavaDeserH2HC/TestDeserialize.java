import java.io.*;
/**
 * Exemplo simples que demonstra a desserialização nativa de um objeto
 * salvo em um arquivo. Observe que, durante a desserialização, o método
 * readObject da classe Alien (que é o tipo do Objeto sendo desserializado)
 * é automaticamente invocado - por isso, chamado de magic method.
 *
 * -----------------------------------------------------------------------
 * Mais detalhes na 12a edição da H2HC (hackers to hackers) magazine:
 * https://www.h2hc.com.br/revista/
 * ----------------------------------------------------------------------- *
 *
 * **** USAGE ****
 *
 * Compilando:
 * $ javac TestDeserialize.java
 *
 * Executando
 * $ java TestDeserialize
 *
 * OBS: lembre de executar o exemplo TestSerialize antes, de forma
 *      a gerar o objeto serializado no arquivo (ET_object.ser), que
 *      será desserializado por este exemplo.
 *
 *
 * @author @joaomatosf
 */
public class TestDeserialize {

    public static void main(String[] args)
            throws IOException, ClassNotFoundException {
        // Obtem stream de bytes a partir do arquivo salvo em disco
        FileInputStream fis = new FileInputStream("ET_object.ser");
        ObjectInputStream ois = new ObjectInputStream(fis);
        // Realiza a desserialização! Nesse momento, os magic methods da classe
        // Alien serão automaticamente invocados! (ie. readObject)
        Alien ET = (Alien) ois.readObject(); // <-- Realiza a desserializacao
        System.out.println("Hi, I'm "+ET.name+" from "+ET.source);

    }
}

