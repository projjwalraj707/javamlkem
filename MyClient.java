import java.security.SecureRandom;
import java.net.InetAddress;
import java.net.Socket;
import java.io.IOException;

import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.CertificateRequest;

public class MyClient {
	public static void main(String[] args) throws Exception {
		TlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
		InetAddress address = InetAddress.getByName("www.google.com");
		int port = 443;
		Socket socket = new Socket(address, port);
		TlsClient client = new DefaultTlsClient(crypto) {
			//Implement TlsClient.getAuthentication();
			public TlsAuthentication getAuthentication() throws IOException {
				return new TlsAuthentication() {
					@Override
					public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
						return;
					}
					@Override
					public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
						return null;
					}
				};
			}
		};
		TlsClientProtocol protocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream());
		
		//Perform a TLS Handshake
		protocol.connect(client);
		protocol.close();
	}
}

