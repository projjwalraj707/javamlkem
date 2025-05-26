import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;
import org.bouncycastle.jsse.BCSSLParameters;

public class CipherSuitesExample {
    public static void main(String[] args) throws Exception {
        // Get the default SSL context
        //SSLContext sslContext = SSLContext.getDefault();

        // Get the socket factory from the context
        //SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        // Get supported cipher suites
        //String[] supportedCipherSuites = socketFactory.getSupportedCipherSuites();

		BCSSLParameters param = new BCSSLParameters();
		String[] supportedCipherSuites = param.getCipherSuites();

        // Print them
        System.out.println("Supported Cipher Suites:");
        for (String suite : supportedCipherSuites) {
            System.out.println(suite);
        }

        // Optionally, you can also set them to SSLParameters
        SSLParameters sslParameters = new SSLParameters();
        sslParameters.setCipherSuites(supportedCipherSuites);
    }
}

