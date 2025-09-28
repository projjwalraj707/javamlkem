import java.security.Security;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MyClient3 {

    public static void enableBCLogging() {
        // Configure the root logger and ensure console handler prints everything
        Logger root = Logger.getLogger("");
        root.setLevel(Level.ALL);
        for (Handler h : root.getHandlers()) {
            h.setLevel(Level.ALL);
        }
        boolean hasConsole = false;
        for (Handler h : root.getHandlers()) {
            if (h instanceof ConsoleHandler) { hasConsole = true; break; }
        }
        if (!hasConsole) {
            ConsoleHandler ch = new ConsoleHandler();
            ch.setLevel(Level.ALL);
            root.addHandler(ch);
        }

        // Turn on BouncyCastle JSSE / TLS logging
        Logger.getLogger("org.bouncycastle.jsse").setLevel(Level.FINEST);
        Logger.getLogger("org.bouncycastle.jsse.provider").setLevel(Level.FINEST);
        Logger.getLogger("org.bouncycastle.jce.provider").setLevel(Level.FINEST);
        Logger.getLogger("org.bouncycastle.tls").setLevel(Level.FINEST);
    }

    public static void main(String[] args) throws Exception {
        // Enable BC logging before providers are registered
        //enableBCLogging();

        // Optional: helps some low-level BC code paths
        System.setProperty("org.bouncycastle.tls.verbose", "true");
        // Example named group property (your original)
        System.setProperty("jdk.tls.namedGroups", "X25519MLKEM768,MLKEM768");

        String HOST_NAME = "www.cloudflare.com";
        int PORT = 443;

        // Register BC providers
        Security.addProvider(new BouncyCastleJsseProvider());
        Security.addProvider(new BouncyCastleProvider());

        // Trust-all for testing only (DO NOT use in production)
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        sslContext.init(null, trustAllCerts, SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));

        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        try (SSLSocket cSock = (SSLSocket) socketFactory.createSocket(HOST_NAME, PORT)) {
            // Start the handshake (this is where TLS logs should appear)
            cSock.startHandshake();

			//Printing CipherSuite
			SSLSession session = cSock.getSession();
			String cipherSuite = session.getCipherSuite();
			System.out.println("The negotiated Cipher Suite is: " + cipherSuite);

            OutputStream os = cSock.getOutputStream();
            InputStream is = cSock.getInputStream();
            String request = "GET / HTTP/1.1\r\n" +
                            "Host: " + HOST_NAME + "\r\n" +
                            "Connection: close\r\n" +
                            "\r\n";
            os.write(request.getBytes(StandardCharsets.UTF_8));
            os.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            String line;
            while ((line = reader.readLine()) != null) {
                // Uncomment to print response body
                // System.out.println(line);
            }
        }
    }
}

