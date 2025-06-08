package chapter15;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class ClassicMcElieceKEMExample
{
    /**
     * Generate a Classic McEliece key pair.
     *
     * @param cmceParameters the Classic McEliece parameter set to use.
     * @return a Classic McEliece key pair.
     */
    public static KeyPair cmceGenerateKeyPair(CMCEParameterSpec cmceParameters)
        throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BCPQC");
        kpg.initialize(cmceParameters, new SecureRandom());

        return kpg.generateKeyPair();
    }

    public static byte[] cmceGeneratePartyU(PublicKey vPubKey, SecretKey secKey)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("CMCE", "BCPQC");

        cipher.init(Cipher.WRAP_MODE, vPubKey, new SecureRandom());

        return cipher.wrap(secKey);
    }

    public static SecretKey cmceGeneratePartyV(
        PrivateKey vPriv, byte[] encapsulation, String keyAlgorithm)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("CMCE", "BCPQC");

        cipher.init(Cipher.UNWRAP_MODE, vPriv);

        return (SecretKey)cipher.unwrap(
                        encapsulation, keyAlgorithm, Cipher.SECRET_KEY);
    }

    public static void main(String[] args)
        throws GeneralSecurityException
    {
        Security.addProvider(new BouncyCastlePQCProvider());

        KeyPair kp = cmceGenerateKeyPair(CMCEParameterSpec.mceliece348864);
        SecretKey aesKey1 = new SecretKeySpec(
                    Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");

        byte[] encKey = cmceGeneratePartyU(kp.getPublic(), aesKey1);

        SecretKey aesKey2 = cmceGeneratePartyV(kp.getPrivate(), encKey, "AES");

        System.out.println("keys match: "
            + Arrays.areEqual(aesKey1.getEncoded(), aesKey2.getEncoded()));
    }
}
