import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.*;
import java.net.Socket;
import java.util.Hashtable;

public class Tls13ClientExample {

    public static void main(String[] args) {
        String host = "www.google.com";
        int port = 443;

        try {
            BcTlsCrypto crypto = new BcTlsCrypto();
            TlsClientProtocol protocol = new TlsClientProtocol(new Socket(host, port).getInputStream(),
                                                               new Socket(host, port).getOutputStream(),
                                                               crypto.getSecureRandom());

            MyTls13Client client = new MyTls13Client(crypto);
            protocol.connect(client);

            // Send HTTP GET request
            OutputStream output = protocol.getOutputStream();
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(output, "UTF-8"), true);
            writer.println("GET / HTTP/1.1");
            writer.println("Host: " + host);
            writer.println("Connection: close");
            writer.println();
            writer.flush();

            // Read the response
            InputStream input = protocol.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input, "UTF-8"));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            protocol.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static class MyTls13Client extends DefaultTlsClient {
        MyTls13Client(BcTlsCrypto crypto) {
            super(crypto);
        }

        @Override
        public Hashtable<Integer, byte[]> getClientExtensions() throws IOException {
            Hashtable<Integer, byte[]> extensions = super.getClientExtensions();
            if (extensions == null) {
                extensions = new Hashtable<>();
            }
            TlsExtensionsUtils.addSupportedVersionsExtensionClient(extensions, ProtocolVersion.TLSv13);
            return extensions;
        }

        @Override
        public ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.TLSv13.downTo(ProtocolVersion.TLSv13);
        }

        @Override
        public void notifyHandshakeComplete() throws IOException {
            super.notifyHandshakeComplete();

            SecurityParameters params = context.getSecurityParameters();

            int cipherSuite = params.getCipherSuite();
            String cipherSuiteName = CipherSuite.getName(cipherSuite);
            System.out.println("Negotiated Cipher Suite: " + cipherSuiteName);

            int namedGroup = params.getNamedGroup();
            if (namedGroup >= 0) {
                String groupName = NamedGroup.getName(namedGroup);
                System.out.println("Key Exchange Group: " + groupName);
            } else {
                System.out.println("Named Group: Not available (might be TLS 1.2 or earlier)");
            }
        }
    }
}
