import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.test.TlsTestUtils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;

public class MinimalTlsServer {
	public static void main(String[] args) throws Exception{
		var PORT = 1234;
		ServerSocket serverSocket = new ServerSocket(PORT);
		System.out.printf("TLS Server started on port %d", PORT);
		while (true) {
			Socket socket = serverSocket.accept();
			TlsServerProtocol tlsServerProtocol = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream());
			TlsCrypto myMlKemCrypto = new BcTlsCrypto(new SecureRandom());
			TlsServer myMlKemTlsServer = new DefaultTlsServer(myMlKemCrypto) {
				protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
					return TlsTestUtils.loadSignerCredentials(
							context, (BcTlsCrypto) myMlKemCrypto, new String[]{"x509-server.pem"}, "x509-server-key.pem");
				}
			};
			tlsServerProtocol.accept(myMlKemTlsServer);
			new PrintStream(tlsServerProtocol.getOutputStream()).println("Hello TLS");
		}
	}
}

