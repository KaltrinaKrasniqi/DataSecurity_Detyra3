import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class TLSClient {
    private static final String HOST = "localhost";
    private static final int PORT = 8443;
    private static final String TRUSTSTORE_PATH = "clienttruststore.jks";
    private static final String TRUSTSTORE_PASSWORD = "Prej1deri8";
    public static final BigInteger P = new BigInteger("23");
    public static final BigInteger G = new BigInteger("5");

    public static void main(String[] args) {
        try {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory socketFactory = sslContext.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) socketFactory.createSocket(HOST, PORT);

            System.out.println("Attempting to establish a secure connection with the server...");

            sslSocket.startHandshake();
            System.out.println("Server certificate received. Verifying...");

            SSLSession sslSession = sslSocket.getSession();
            java.security.cert.Certificate[] serverCerts = sslSession.getPeerCertificates();
            java.security.cert.X509Certificate serverCert = (java.security.cert.X509Certificate) serverCerts[0];
            serverCert.checkValidity();
            System.out.println("Server certificate is valid.");
            System.out.println("SSL/TLS handshake successful. Secure communication channel established.");

            PrintWriter out = new PrintWriter(sslSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));

            BigInteger clientPrivateKey = generateDHPrivateKey();
            BigInteger clientPublicKey = G.modPow(clientPrivateKey, P);

            String serverPublicKeyStr = reader.readLine();
            BigInteger serverPublicKey = new BigInteger(serverPublicKeyStr);

            out.println(clientPublicKey.toString());

            BigInteger sharedSecret = serverPublicKey.modPow(clientPrivateKey, P);


            System.out.println("Echanged key: "+sharedSecret);

            // Generate AES encryption key from shared secret
            byte[] sharedSecretBytes = sharedSecret.toByteArray();
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
            String userInput;
            while ((userInput = in.readLine()) != null) {
                // Encrypt user input
                byte[] encryptedBytes = encryptCipher.doFinal(userInput.getBytes());
                String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);

                // Send encrypted message to server
                out.println(encryptedMessage);

                // Receive response from server
                String serverResponse = reader.readLine();
                System.out.println("From Server (Encrypted): " + serverResponse);

                // Decrypt server response
                byte[] serverResponseBytes = Base64.getDecoder().decode(serverResponse);
                String decryptedMessage = new String(decryptCipher.doFinal(serverResponseBytes));

                System.out.println("Decrypted Message: " + decryptedMessage);

                // exit in console to exit
                if ("exit".equalsIgnoreCase(userInput)) break;
            }

            sslSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static BigInteger generateDHPrivateKey() {
        return new BigInteger(512, new java.security.SecureRandom());
    }
}