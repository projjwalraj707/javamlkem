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
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.bouncycastle.util.Strings;

public class SPHINCSPlusExample
{
    /**
     * Generate a SPHINCS+ key pair.
     * 
     * @param sphincsPlusParameterSpec SPHINCS+ parameter set to use.
     * @return a SPHINCS+ key pair.
     */
    public static KeyPair generateSPHINCSPlusKeyPair(
        SPHINCSPlusParameterSpec sphincsPlusParameterSpec)
        throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(sphincsPlusParameterSpec, new SecureRandom());

        return kpg.generateKeyPair();
    }

    /**
     * Generate an encoded SPHINCS+ signature using the passed in SPHINCS+ private key
     * and input data.
     *
     * @param spxPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateSPHINCSPlusSignature(
        PrivateKey spxPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SPHINCSPlus", "BCPQC");

        signature.initSign(spxPrivate);

        signature.update(input);

        return signature.sign();
    }

    /**
     * Return true if the passed in SPHINCS+ signature verifies against
     * the passed in SPHINCS+ public key and input.
     *
     * @param spxPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifySPHINCSPlusSignature(
        PublicKey spxPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SPHINCSPlus", "BCPQC");

        signature.initVerify(spxPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    public static void main(String[] args)
        throws GeneralSecurityException
    {
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyPair spxKp = generateSPHINCSPlusKeyPair(
                                    SPHINCSPlusParameterSpec.sha2_128f);

        byte[] sphincsPlusSig = generateSPHINCSPlusSignature(
                        spxKp.getPrivate(), Strings.toByteArray("hello, world!"));

        System.out.println("SPHINCS+ verified: " + verifySPHINCSPlusSignature(
            spxKp.getPublic(), Strings.toByteArray("hello, world!"), sphincsPlusSig));
    }
}
