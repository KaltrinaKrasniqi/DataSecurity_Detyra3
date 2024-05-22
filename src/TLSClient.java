import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

public class TLSClient {
    private static final String HOST = "localhost";
    private static final int PORT = 8443;
    private static final String TRUSTSTORE_PATH = "clienttruststore.jks";
    private static final String TRUSTSTORE_PASSWORD = "Prej1deri8";
    //Diffie Hellman (keto t njejta met Serverit)
    public static final BigInteger P = new BigInteger("23");
    public static final BigInteger G = new BigInteger("5");

    public static void main(String[] args) {
        try {
            //tash klienti e ka trustStore (me pas pasin korrekt, portin)
            KeyStore trustStore = KeyStore.getInstance("JKS");
            
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());

            //Njejt s sikurse KeyMenager klienti ka TrustMenager
            TrustManagerFactory menager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            menager.init(trustStore);

            SSLContext tls = SSLContext.getInstance("TLS");
            
            tls.init(null, menager.getTrustManagers(), null);

            //kish ba edhe pa factory amo ma leht menagjohet
            SSLSocketFactory socketFactory = tls.getSocketFactory();

            SSLSocket sslSocket = (SSLSocket) socketFactory.createSocket(HOST, PORT);

            System.out.println("Attempting to establish a secure connection with the server...");

            sslSocket.startHandshake();
            //Momentin qe s gjun error, handhake u kompletu
            System.out.println("Server certificate received. Verifying...");


            SSLSession sslSession = sslSocket.getSession();

            //Certifikata e cila u vendos nga keytool vendoset ne objekt
            Certificate[] serverCerts = sslSession.getPeerCertificates();
            X509Certificate certificate = (X509Certificate) serverCerts[0];

            certificate.checkValidity();  //Nese gjun erro i bje qe jo valide

            System.out.println("Server certificate is valid.");
            System.out.println("SSL/TLS handshake successful. Secure communication channel established.");

            //Me shkru serverit mesazhe
            PrintWriter writeServer = new PrintWriter(sslSocket.getOutputStream(), true);

            //Me marr mesazhe nga
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            BufferedReader readFromServer = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));

            //Diffie hellMan - Si ne ligjerata
            BigInteger A = generateDHPrivateKey();
            BigInteger clientPublicKey = G.modPow(A, P);

            String serverPublicKeyStr = readFromServer.readLine();

            BigInteger serverPublicKey = new BigInteger(serverPublicKeyStr);

            writeServer.println(clientPublicKey.toString());

            BigInteger exchangedKey = serverPublicKey.modPow(A, P);


            System.out.println("Echanged key: "+exchangedKey);

            // Generate AES encryption key from shared secret
            byte[] keyNeByte = exchangedKey.toByteArray();

            // Qelesi shum i vogel, AES celesi eshte 128 bit Prandaj e bajm hash
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            keyNeByte = sha.digest(keyNeByte);
            keyNeByte = Arrays.copyOf(keyNeByte, 16); // vew 128 t parat i merr (16*8bit = 128)
            SecretKey celesiSekretAES = new SecretKeySpec(keyNeByte, "AES");

            // E bejme gati viper per enkriptim e dekriptim tani veq e thirrum pasi qelsi ska me ndryshu gjat sesionit
            Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, celesiSekretAES);

            Cipher decryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, celesiSekretAES);

            // Communication loop
            String userInput;
            while ((userInput = in.readLine()) != null) {
                // Enkripton inputin e userit
                byte[] encryptedBytes = encryptCipher.doFinal(userInput.getBytes());

                String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);

                // Dergon Mesazhin serverit te enkriptum
                writeServer.println(encryptedMessage);

                // Merr pergjigjet
                String serverResponse = readFromServer.readLine();

                System.out.println("From Server (Encrypted): " + serverResponse);

                // Dekripton pergjigjet e enkriptuara nga serveri
                byte[] serverResponseBytes = Base64.getDecoder().decode(serverResponse);

                String decryptedMessage = new String(decryptCipher.doFinal(serverResponseBytes));

                System.out.println("Decrypted Message: " + decryptedMessage);

                // Me exit ndalet programi
                if ("exit".equalsIgnoreCase(userInput)) break;
            }

            sslSocket.close();
        } catch (Exception e) {
            System.err.println("Error...");
            e.printStackTrace();
        }
    }

    private static BigInteger generateDHPrivateKey() {
        return new BigInteger(512, new java.security.SecureRandom());
    }
}