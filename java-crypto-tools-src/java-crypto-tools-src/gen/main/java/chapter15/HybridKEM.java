package chapter15;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.newhope.NHSecretKeyProcessor;
import org.bouncycastle.util.encoders.Hex;

public class HybridKEM
{
    static class WrappedWithSecret
    {
        private final byte[] wrapped;
        private final SecretKeySpec processedKey;

        public WrappedWithSecret(byte[] wrapped, SecretKeySpec processedKey)
        {
            this.wrapped = wrapped;
            this.processedKey = processedKey;
        }
    }

    static class PartyU
    {
        private final NHSecretKeyProcessor.PartyUBuilder processor;

        PartyU(SecureRandom random)
        {
            processor = new NHSecretKeyProcessor.PartyUBuilder(random);
        }

        public byte[] doStage1()
        {
            return processor.getPartA();
        }

        public WrappedWithSecret wrapKey(PublicKey vKey, byte[] partBInfo, SecretKey key)
            throws GeneralSecurityException, IOException
        {
            Cipher c = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding");

            c.init(Cipher.ENCRYPT_MODE, vKey);

            byte[] keyEnc = key.getEncoded();

            try
            {
                return new WrappedWithSecret(c.doFinal(key.getEncoded()),
                    new SecretKeySpec(processor.build(partBInfo).processKey(keyEnc), key.getAlgorithm()));
            }
            finally
            {
                Arrays.fill(keyEnc, (byte)0);
            }
        }
    }

    static class PartyV
    {
        private final KeyPair kp;
        private final NHSecretKeyProcessor.PartyVBuilder processor;

        PartyV(SecureRandom random)
            throws GeneralSecurityException
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

            kpGen.initialize(2048, random);

            this.kp = kpGen.generateKeyPair();

            processor = new NHSecretKeyProcessor.PartyVBuilder(random);
        }

        public PublicKey getPublic()
        {
            return kp.getPublic();
        }

        public byte[] doStage2(byte[] partAInfo)
        {
            return processor.getPartB(partAInfo);
        }

        public SecretKey unwrapKey(byte[] wrappedKey, String algorithm)
            throws GeneralSecurityException, IOException
        {
            Cipher c = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding");

            c.init(Cipher.DECRYPT_MODE, kp.getPrivate());

            byte[] initialKey = c.doFinal(wrappedKey);
            try
            {
                return new SecretKeySpec(processor.build().processKey(initialKey), algorithm);
            }
            finally
            {
                Arrays.fill(initialKey, (byte)0);
            }
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        SecureRandom random = new SecureRandom();

        PartyU partyU = new PartyU(random);

        PartyV partyV = new PartyV(random);

        SecretKey secKey = new SecretKeySpec(Hex.decode("0102030405060708090a0b0c0d0e0f"), "AES");

        WrappedWithSecret processed = partyU.wrapKey(partyV.getPublic(), partyV.doStage2(partyU.doStage1()), secKey);

        System.err.println(Hex.toHexString(processed.processedKey.getEncoded()));
        System.err.println(Hex.toHexString(partyV.unwrapKey(processed.wrapped, secKey.getAlgorithm()).getEncoded()));
    }
}
