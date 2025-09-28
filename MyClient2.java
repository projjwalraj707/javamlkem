import java.security.Security;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MyClient2 {
	public static void main(String[] args) throws Exception {
		System.setProperty("jdk.tls.namedGroups", "X25519MLKEM768");
		System.setProperty("org.bouncycastle.tls.verbose", "true");

		String HOST_NAME = "www.cloudflare.com";
		int PORT = 443;

		Security.addProvider(new BouncyCastleJsseProvider());
		Security.addProvider(new BouncyCastleProvider());

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
			//System.out.println(line);
		}
		cSock.close();
	}
}
