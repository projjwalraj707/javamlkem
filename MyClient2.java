import java.security.Security;
import java.security.SecureRandom;
import java.security.KeyStore;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Properties;

//import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.util.Strings;

public class MyClient2 {
	public static  void main(String[] args) throws Exception {
		Properties props = System.getProperties();
		props.setProperty("jdk.tls.namedGroups", "X25519MLKEM768");
		String HOST_NAME = "www.instagram.com";
		int PORT = 443;
		Security.addProvider(new BouncyCastleJsseProvider());
		SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "BCJSSE");
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
		trustManagerFactory.init((KeyStore) null);
		sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
		SSLSocketFactory socketFactory = sslContext.getSocketFactory();
		SSLSocket cSock = (SSLSocket) socketFactory.createSocket(HOST_NAME, PORT);
		cSock.startHandshake();
		
		OutputStream os = cSock.getOutputStream();
		InputStream is = cSock.getInputStream();
		String request = "GET / HTTP/1.1\r\n" +
						"Host: " + HOST_NAME + "\r\n" +
						"Connection: close\r\n" +
						"\r\n";
		os.write(request.getBytes("UTF-8"));
		os.flush();

		BufferedReader reader = new BufferedReader(new InputStreamReader(is));
		String line;
		while ((line = reader.readLine()) != null) {
			System.out.println(line);
		}
		cSock.close();
	}
}
