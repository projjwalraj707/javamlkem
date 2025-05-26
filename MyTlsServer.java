import org.bouncycastle.tls.DefaultTlsServer;

public class MyTlsServer extends DefaultTlsServer {

    public void printSupportedCipherSuites() {
        int[] cipherSuites = getSupportedCipherSuites();

        System.out.println("Supported Cipher Suites:");
        for (int suite : cipherSuites) {
            System.out.printf("0x%04X%n", suite);
        }
    }

    public static void main(String[] args) {
        MyTlsServer server = new MyTlsServer();
        server.printSupportedCipherSuites();
    }
}
