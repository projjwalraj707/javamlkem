import java.security.SecureRandom;
import java.net.InetAddress;
import java.net.Socket;
import java.io.*;
import java.util.Properties;
import java.util.Vector;

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
import org.bouncycastle.tls.*;
import org.bouncycastle.util.Integers;

public class MyClient {
	public static void main(String[] args) throws Exception {
		//Properties prop = System.getProperties();
		//prop.list(System.out);
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
			public Vector getSupportedGroups(Vector paramVector) {
				Vector v = new Vector();
				v.addElement(Integers.valueOf(NamedGroup.X25519MLKEM768));
				return v;
			}
		};
		TlsClientProtocol protocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream());
		
		//Perform a TLS Handshake
		protocol.connect(client);
		OutputStream output = protocol.getOutputStream();
		output.write("GET / HTTP/1.1\r\n".getBytes("UTF-8"));
		output.write("HOST: www.google.com\r\n".getBytes("UTF-8"));
		output.write("\r\n".getBytes("UTF-8"));
		output.flush();

		InputStream input = protocol.getInputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(input));
		String line;
		while ((line = reader.readLine()) != null)
			System.out.println(line);
		protocol.close();
	}
}

