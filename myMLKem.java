import java.security.SecureRandom;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;

public class myMLKem {
	public static void main(String[] args) {
		var rand = new SecureRandom();
		var keyGenParam = new MLKEMKeyGenerationParameters(rand, MLKEMParameters.ml_kem_768);
		var mlkemKeyPairGenerator = new MLKEMKeyPairGenerator();
		mlkemKeyPairGenerator.init(keyGenParam);
		var keyPair = mlkemKeyPairGenerator.generateKeyPair();
		System.out.println(keyPair);
	}
}
