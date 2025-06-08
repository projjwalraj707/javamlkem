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
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;
import org.bouncycastle.util.Arrays;

public class FrodoKEMExample
{
    public static KeyPair frodoGenerateKeyPair(FrodoParameterSpec frodoParameters)
        throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Frodo", "BCPQC");
        kpg.initialize(frodoParameters, new SecureRandom());

        return kpg.generateKeyPair();
    }

    public static SecretKeyWithEncapsulation frodoGeneratePartyU(PublicKey vPubKey)
        throws GeneralSecurityException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("Frodo", "BCPQC");

        keyGen.init(new KEMGenerateSpec(vPubKey, "AES"), new SecureRandom());

        return (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    public static SecretKeyWithEncapsulation frodoGeneratePartyV(
        PrivateKey vPriv, byte[] encapsulation)
        throws GeneralSecurityException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("Frodo", "BCPQC");

        keyGen.init(new KEMExtractSpec(vPriv, encapsulation, "AES"));

        return (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    public static void main(String[] args)
        throws GeneralSecurityException
    {
        Security.addProvider(new BouncyCastlePQCProvider());

        KeyPair kp = frodoGenerateKeyPair(FrodoParameterSpec.frodokem640aes);

        SecretKeyWithEncapsulation secEnc1 = frodoGeneratePartyU(kp.getPublic());

        SecretKeyWithEncapsulation secEnc2 = frodoGeneratePartyV(
                            kp.getPrivate(), secEnc1.getEncapsulation());

        System.out.println("secrets match: "
            + Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }
}
