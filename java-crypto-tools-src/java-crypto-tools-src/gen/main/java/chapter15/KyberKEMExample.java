package chapter15;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyGenerator;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.Arrays;

public class KyberKEMExample
{
    public static KeyPair kyberGenerateKeyPair(KyberParameterSpec kyberParameters)
        throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(kyberParameters, new SecureRandom());

        return kpg.generateKeyPair();
    }

    public static SecretKeyWithEncapsulation kyberGeneratePartyU(PublicKey vPubKey)
        throws GeneralSecurityException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC");

        keyGen.init(new KEMGenerateSpec(vPubKey, "AES"), new SecureRandom());

        return (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    public static SecretKeyWithEncapsulation kyberGeneratePartyV(
        PrivateKey vPriv, byte[] encapsulation)
        throws GeneralSecurityException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC");

        keyGen.init(new KEMExtractSpec(vPriv, encapsulation, "AES"));

        return (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    public static void main(String[] args)
        throws GeneralSecurityException
    {
        Security.addProvider(new BouncyCastlePQCProvider());

        KeyPair kp = kyberGenerateKeyPair(KyberParameterSpec.kyber1024);

        SecretKeyWithEncapsulation secEnc1 = kyberGeneratePartyU(kp.getPublic());

        SecretKeyWithEncapsulation secEnc2 = kyberGeneratePartyV(
                            kp.getPrivate(), secEnc1.getEncapsulation());

        System.out.println("secrets match: "
            + Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }
}
