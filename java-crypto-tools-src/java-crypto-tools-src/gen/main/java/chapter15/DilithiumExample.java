package chapter15;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.util.Strings;

public class DilithiumExample
{
    /**
     * Generate a Dilithium key pair.
     * 
     * @param dilithiumPlusParameterSpec Dilithium parameter set to use.
     * @return a Dilithium key pair.
     */
    public static KeyPair generateDilithiumKeyPair(
        DilithiumParameterSpec dilithiumPlusParameterSpec)
        throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        kpg.initialize(dilithiumPlusParameterSpec, new SecureRandom());

        return kpg.generateKeyPair();
    }

    /**
     * Generate an encoded Dilithium signature using the passed in Dilithium private
     * key and input data.
     *
     * @param dilPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateDilithiumSignature(
        PrivateKey dilPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("Dilithium", "BCPQC");

        signature.initSign(dilPrivate);

        signature.update(input);

        return signature.sign();
    }

    /**
     * Return true if the passed in Dilithium signature verifies against
     * the passed in Dilithium public key and input.
     *
     * @param dilPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyDilithiumSignature(
        PublicKey dilPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("Dilithium", "BCPQC");

        signature.initVerify(dilPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    public static void main(String[] args)
        throws GeneralSecurityException
    {
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyPair dilKp = generateDilithiumKeyPair(
                                    DilithiumParameterSpec.dilithium2);

        byte[] dilithiumSignature = generateDilithiumSignature(
                        dilKp.getPrivate(), Strings.toByteArray("hello, world!"));

        System.out.println("Dilithiun verified: " + verifyDilithiumSignature(
            dilKp.getPublic(), Strings.toByteArray("hello, world!"),
	                                                 dilithiumSignature));
    }
}
