import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;


//Keto hapa se pari ekzekutohen ne COnsole

//Krijimi i Keystore të Serverit:
//keytool -genkeypair -alias serverkey -keyalg RSA -keystore serverkeystore.jks -keysize 2048 -validity 365

//Krijimi i Truststore të Klientit - eksporti i certifikates per serverin:
//keytool -export -alias serverkey -file servercert.cer -keystore serverkeystore.jks

//Importi i certifikatës në truststore të klientit
//keytool -import -alias servercert -file servercert.cer -keystore clienttruststore.jks


public class TLSServer {

    private static final int PORT = 8443; //Porti i komunikimit
    private static final String KEYSTORE_PATH = "serverkeystore.jks";
    private static final String KEYSTORE_PASSWORD = "Prej1deri8";
    //Diffie and Hellman
    public static final BigInteger P = new BigInteger("23");
    public static final BigInteger G = new BigInteger("5");

    public static void main(String[] args) {
        try {
            //Ketu krijohet instance e JavaKeyStore (DEFAULT PER JAVA)
            KeyStore keyStore = KeyStore.getInstance("JKS");

            keyStore.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            //Pranon char Array per me shti n password

            KeyManagerFactory menager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            //Zakonisht platforma eshte ("SunX509" ne Java).
            menager.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            SSLContext tls = SSLContext.getInstance("TLS"); //Na jena tu perdor protokolin TLS
            tls.init(menager.getKeyManagers(), null, null);

            SSLServerSocketFactory serverSocketFactory = tls.getServerSocketFactory();
            //Veq e abstrahon qat SSLContext per manovrim mat leht
            //Krijon ni soket t severit n qat port
            SSLServerSocket socket = (SSLServerSocket) serverSocketFactory.createServerSocket(PORT);

            System.out.println("Server started and listening for connections...");

            while (true) {
                SSLSocket soketiKlientit = (SSLSocket)socket.accept();

                handleClient(soketiKlientit);

                soketiKlientit.close();
            }
        } catch (Exception e) {
            System.out.println("Error in accepting Client Messages");
            e.printStackTrace();
        }
    }

    private static void handleClient(SSLSocket clientSocket) {
        try {
            clientSocket.startHandshake();
            //inicon handshake

            System.out.println("Sending server certificate...");

            SSLSession sslSession = clientSocket.getSession();

            System.out.println("Client has verified the certificate. Handshake complete.");

            //kanali komunikues midis klientit dhe serverit është i sigurt.

            //Merr dhena nga klienti
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            //Dergon t dhena te klienti
            PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);

            //DIffie Hellman (si ne ushtrime)
            BigInteger A = generateDHPrivateKey();
            BigInteger serverPublicKey = G.modPow(A, P);
            writer.println(serverPublicKey.toString());

            String clientPublicKeyStr = reader.readLine();
            BigInteger clientPublicKey = new BigInteger(clientPublicKeyStr);

            BigInteger exchangedKey = clientPublicKey.modPow(A, P);

            System.out.println("Exchanged key:" + exchangedKey);

            // Prej qelesit te shkembym me Diffie Hellman e enkriptojm me AES

            byte[] keyNeByte = exchangedKey.toByteArray();

            // Qelesi shum i vogel, AES celesi eshte 128 bit Prandaj e bajm hash
            MessageDigest hashICelesit = MessageDigest.getInstance("SHA-256");
            keyNeByte = hashICelesit.digest(keyNeByte);
            //Veq 128 bitat e par i merr t hashit (SHA i jep 256)
            keyNeByte = Arrays.copyOf(keyNeByte, 16); // Use only first 128 bits for AES
            SecretKey celesiSekretAES = new SecretKeySpec(keyNeByte, "AES");


            // E bejme gati viper per enkriptim e dekriptim tani veq e thirrum pasi qelsi ska me ndryshu gjaat sesionit
            Cipher enkriptedCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            enkriptedCipher.init(Cipher.ENCRYPT_MODE, celesiSekretAES);

            Cipher decryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, celesiSekretAES);

            // Communication loop
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("From Client (Encrypted): " + line);

                // Mesazhet e marra dekriptoji (celesi i bjen mu kan i njejti prej Diffie - Hellman)
                byte[] encryptedBytes = Base64.getDecoder().decode(line); //Base 64

                byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);

                String messazhiDekriptum = new String(decryptedBytes);

                System.out.println("Decrypted Message: " + messazhiDekriptum);

                // Tash pergjigjjet e serverit enkriptojm prap
                String response = "From Server: " + messazhiDekriptum;

                byte[] encryptedResponse = enkriptedCipher.doFinal(response.getBytes());

                String pergjigjjaDekriptum = Base64.getEncoder().encodeToString(encryptedResponse);

                writer.println(pergjigjjaDekriptum);

                if ("exit".equalsIgnoreCase(messazhiDekriptum)) break; // Me dal prej programit exit
            }
        } catch (Exception e) {
            System.err.println("Error in handling client: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
            }
        }
    }

    private static BigInteger generateDHPrivateKey() {
        return new BigInteger(512, new java.security.SecureRandom());
    }

}