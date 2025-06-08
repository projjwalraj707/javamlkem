import java.security.SecureRandom;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.NamedGroup;

public class DoesSupportPQC {
	public static void main(String[] args) {
		TlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
		if (crypto.hasNamedGroup(NamedGroup.MLKEM512)) System.out.println("Congrats! This version of BC supports PQC TLS.");
		else System.out.println("Sadly, This version of BC does NOT support PQC TLS!");
	}
}

