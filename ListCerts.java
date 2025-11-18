import java.security.Security;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class ListCerts {
	public static void main(String[] args) throws Exception {
		KeyStore windowsKeyStore = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
		windowsKeyStore.load(null, null);

		Enumeration<String> aliases = windowsKeyStore.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			X509Certificate cert = (X509Certificate) windowsKeyStore.getCertificate(alias);
			System.out.println("Alias: " + alias);
			System.out.println("Subject: " + cert.getSubjectDN());
			System.out.println("Issue: " + cert.getIssuerDN());
			System.out.println("Valid from: " + cert.getNotBefore() + "to " + cert.getNotAfter());
			System.out.println("_______________________________");
		}
	}
}

