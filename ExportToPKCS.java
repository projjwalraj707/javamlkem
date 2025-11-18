import java.security.Security;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;

import java.util.Enumeration;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.SSLContext;

public class ExportToPKCS {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleJsseProvider());
		Security.addProvider(new BouncyCastleProvider());

		KeyStore windowsKeyStore = KeyStore.getInstance("Windows-MY");
		windowsKeyStore.load(null, null);
		Provider sunProvider = windowsKeyStore.getProvider();
		System.out.println(sunProvider.getName());
		/*
		String alias = "c90b6e56-66c2-4cd8-b614-122f2c75ffdb";
		alias = "piyus";
		X509Certificate cert = (X509Certificate) windowsKeyStore.getCertificate(alias);
		System.out.println("Alias: " + alias);
		System.out.println("Subject: " + cert.getSubjectDN());
		System.out.println("Issue: " + cert.getIssuerDN());
		System.out.println("Valid from: " + cert.getNotBefore() + "to " + cert.getNotAfter());
		System.out.println("_______________________________");

		PrivateKey privateKey = (PrivateKey) windowsKeyStore.getKey(alias, null);
		Certificate[] certChain = windowsKeyStore.getCertificateChain(alias);

		*/
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm(), "BCJSSE");
		tmf.init(windowsKeyStore);
		TrustManager[] trustManagers = tmf.getTrustManagers();
		SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "BCJSSE");
		sslContext.init(null, trustManagers, SecureRandom.getInstance("DEFAULT", "BC"));
	}
}

