# SSL/TLS Handshake Simulation with Certificate Verification Console Application

This project was made for assignment 3 in Data Security class 2024

## How to execute the program

1.  Ensure that you have the JDK installed on your machine. You can download it from the official Oracle website or use an open-source alternative like OpenJDK.
2.  Make sure that the JAVA_HOME environment variable is set, and the bin directory of your JDK is added to your PATH.
3.  After downloading all the files, you can execute with command prompt first compile it with javac then run it with java or a Java idea like IntelliJ.
4.  Make sure you are in the same directory as your compiled class files.

###  If you encounter any issues, ensure that:

1. Your Java files are named correctly and match the class names.
2. All necessary dependencies are included in the classpath.

# Description of the SSL/TLS Handshake Simulation

TLS, or transport layer security, is a protocol used across the globe to encrypt and secure communication over the internet.
TLS and its predecessor SSL (secure socket layer) are the most commonly used cryptographic protocols for providing encryption, authenticity, and integrity, which enables end-to-end security of data sent between applications over the internet.
Historically, internet communication has happened in plain text with minimal security. This means that the data you sent to a server was visible over the wire, leaving it open to man-in-the-middle attacks.

To solve this type of problem, SSL and TLS were introduced. They provide three primary benefits:

* Integrity Protection: TLS protects against modification of messages by an active wiretapper.
* Authentication: In most modes, TLS provides peer authentication using signed certificates. Servers are usually authenticated, and clients may be authenticated as requested by servers. This authentication happens as part of the TLS handshake.
* Confidentiality: TLS encrypts data being sent between client and server, protecting the confidentiality and privacy of data. This ensures that passive wiretappers won't see sensitive data shared between the machines.

### TLS Handshake

An SSL or TLS handshake is a series of actions carried out by the client and server that authenticates them to each other, and establishes the secret keys they'll use to interact.

## Client

* The client application prepares to connect to a server over SSL/TLS.
* It sets up the necessary SSL/TLS configurations, such as selecting an appropriate SSLSocketFactory.
* The client sends a ClientHello message to the server, this message includes information such as the SSL/TLS version, supported cipher suites, and other SSL/TLS options.
* The server sends its certificate to the client as part of the handshake.
* The client receives the server's certificate and begins the verification process.
* The client checks the server's certificate validity.
* The client and server perform a key exchange to establish a shared secret. This can involve different mechanisms, such as the Diffie-Hellman key exchange.
* The client sends a Finished message encrypted with the session key, signaling the end of the handshake.
* Once the server responds with its Finished message, the handshake is complete.


## Server

* The server prepares to accept SSL/TLS connections.
* It sets up necessary configurations, such as loading the server certificate and private key.
* The server receives the ClientHello message from the client.
* The server responds with a ServerHello message.
* The server sends its certificate to the client.
* The server waits for the client's key exchange message, it decrypts the pre-master secret using its private key.
* The server sends a Finished message encrypted with the session key, signaling the end of the handshake.
* Once the client responds with its Finished message, the handshake is complete.

# Examples from Execution













