import java.security.SecureRandom;

import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

public class MLKEM {
	public static void main(String[] args) throws Exception {
		SecureRandom secureRandom = new SecureRandom();
		MLKEMKeyGenerationParameters mlkemKeyGenParam = new MLKEMKeyGenerationParameters(secureRandom, MLKEMParameters.ml_kem_768);
		MLKEMKeyPairGenerator mlKemKeyPairGen = new MLKEMKeyPairGenerator();
		mlKemKeyPairGen.init(mlkemKeyGenParam);
		AsymmetricCipherKeyPair keyPair = mlKemKeyPairGen.generateKeyPair();

		MLKEMPrivateKeyParameters prvKey = (MLKEMPrivateKeyParameters) keyPair.getPrivate();
		MLKEMPublicKeyParameters pubKey = (MLKEMPublicKeyParameters) keyPair.getPublic();

		//System.out.println(prvKey);
		//System.out.println(pubKey);
		
		//encapsulation
		MLKEMGenerator mlkemGenerator = new MLKEMGenerator(secureRandom);
		SecretWithEncapsulation secretEncapsulation = mlkemGenerator.generateEncapsulated(pubKey);
		byte[] cipherText = secretEncapsulation.getEncapsulation();
		byte[] sharedSec1 = secretEncapsulation.getSecret();

		//decapsulation
		MLKEMExtractor mlkemExtractor = new MLKEMExtractor(prvKey);
		byte[] sharedSec2 = mlkemExtractor.extractSecret(cipherText);
		
		System.out.println(sharedSec1);
		System.out.println(sharedSec2);
	}
}

