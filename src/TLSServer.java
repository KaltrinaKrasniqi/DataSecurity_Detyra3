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
    private static final int PORT = 8443;
    private static final String KEYSTORE_PATH = "serverkeystore.jks";
    private static final String KEYSTORE_PASSWORD = "Prej1deri8";
    public static final BigInteger P = new BigInteger("23");
    public static final BigInteger G = new BigInteger("5");

    public static void main(String[] args) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(PORT);

            System.out.println("Server started and listening for connections...");

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                handleClient(clientSocket);
                clientSocket.close();
            }
        } catch (Exception e) {
            System.out.println("Error in accepting Client Messages");
            e.printStackTrace();
        }
    }

    private static void handleClient(SSLSocket sslSocket) {
        try {
            sslSocket.startHandshake();

            System.out.println("Sending server certificate...");

            SSLSession sslSession = sslSocket.getSession();

            System.out.println("Client has verified the certificate. Handshake complete.");

            BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
            PrintWriter writer = new PrintWriter(sslSocket.getOutputStream(), true);

            BigInteger A = generateDHPrivateKey();
            BigInteger serverPublicKey = G.modPow(A, P);
            writer.println(serverPublicKey.toString());

            String clientPublicKeyStr = reader.readLine();
            BigInteger clientPublicKey = new BigInteger(clientPublicKeyStr);

            BigInteger exchangedKey = clientPublicKey.modPow(A, P);

            System.out.println("Exchanged key:" + exchangedKey);
            // Generate AES encryption key from shared secret
            byte[] sharedSecretBytes = exchangedKey.toByteArray();
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sharedSecretBytes = sha.digest(sharedSecretBytes);
            sharedSecretBytes = Arrays.copyOf(sharedSecretBytes, 16); // Use only first 128 bits for AES
            SecretKey secretKey = new SecretKeySpec(sharedSecretBytes, "AES");

            // Initialize AES cipher for encryption and decryption
            Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);

            Cipher decryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);

            // Communication loop
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("From Client (Encrypted): " + line);

                // Decrypt received message
                byte[] encryptedBytes = Base64.getDecoder().decode(line);
                byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);
                String decryptedMessage = new String(decryptedBytes);

                System.out.println("Decrypted Message: " + decryptedMessage);

                // Encrypt response message
                String response = "From Server: " + decryptedMessage;
                byte[] encryptedResponse = encryptCipher.doFinal(response.getBytes());
                String encryptedResponseStr = Base64.getEncoder().encodeToString(encryptedResponse);

                writer.println(encryptedResponseStr);

                // exit in console to exit
                if ("exit".equalsIgnoreCase(decryptedMessage)) break;
            }
        } catch (Exception e) {
            System.err.println("Error in handling client: " + e.getMessage());
        } finally {
            try {
                sslSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
            }
        }
    }

    private static BigInteger generateDHPrivateKey() {
        return new BigInteger(512, new java.security.SecureRandom());
    }

}