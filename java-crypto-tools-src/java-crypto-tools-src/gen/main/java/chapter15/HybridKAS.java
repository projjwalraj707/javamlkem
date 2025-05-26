package chapter15;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.newhope.NHOtherInfoGenerator;
import org.bouncycastle.pqc.crypto.util.PQCOtherInfoGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

public class HybridKAS
{
    static
    public class KasParty
    {
        protected final KeyPair kp;

        KasParty(SecureRandom random)
            throws GeneralSecurityException
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

            kpGen.initialize(new ECGenParameterSpec("P-256"), random);

            this.kp = kpGen.generateKeyPair();
        }

        public PublicKey getPublic()
        {
            return kp.getPublic();
        }
    }

    static
    public class PartyU
        extends KasParty
    {
        PQCOtherInfoGenerator.PartyU infoGenerator;

        PartyU(SecureRandom random, byte[] uInfo, byte[] vInfo)
            throws GeneralSecurityException
        {
            super(random);

            infoGenerator = new PQCOtherInfoGenerator.PartyU(
                KyberParameters.kyber512,
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
                uInfo, vInfo, random);
        }

        /**
         * Return the initiator stage 1 value for the NewHope agreement.
         * @return a byte[] based on a NewHope public key.
         */
        public byte[] doStage1()
        {
            return infoGenerator.getSuppPrivInfoPartA();
        }

        /**
         * Return the KDF generated agreed value based on the responses from V.
         *
         * @param otherKey the V party EC key.
         * @param partBInfo the V party NewHope response.
         * @return the KDF generated secret from the agreement.
         */
        public byte[] doAgreement(PublicKey otherKey, byte[] partBInfo)
            throws GeneralSecurityException, IOException
        {
            KeyAgreement agreement = KeyAgreement.getInstance(
                                        "ECCDHwithSHA256KDF", "BC");

            agreement.init(kp.getPrivate(),
                new UserKeyingMaterialSpec(
                        infoGenerator.generate(partBInfo).getEncoded()));

            agreement.doPhase(otherKey, true);

            return agreement.generateSecret();
        }
    }

    static
    public class PartyV
        extends KasParty
    {
        PQCOtherInfoGenerator.PartyV infoGenerator;

        PartyV(SecureRandom random, byte[] uInfo, byte[] vInfo)
            throws GeneralSecurityException
        {
            super(random);

            infoGenerator = new PQCOtherInfoGenerator.PartyV(
                KyberParameters.kyber512,
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
                uInfo, vInfo, random);
        }

        /**
         * Return the NewHope based response to U's initial value.
         *
         * @param partAInfo the NewHope based agreed response.
         * @return the response value to pass to U.
         */
        public byte[] doStage2(byte[] partAInfo)
        {
            return infoGenerator.getSuppPrivInfoPartB(partAInfo);
        }

        /**
         * Return the KDF generated agreed value based on the U public key.
         *
         * @param otherKey the U party EC key.
         * @return the KDF generated secret from the agreement.
         */
        public byte[] doAgreement(PublicKey otherKey)
            throws GeneralSecurityException, IOException
        {
            KeyAgreement agreement = KeyAgreement.getInstance(
                                                "ECCDHwithSHA256KDF", "BC");

            agreement.init(kp.getPrivate(), new UserKeyingMaterialSpec(
                                    infoGenerator.generate().getEncoded()));

            agreement.doPhase(otherKey, true);

            return agreement.generateSecret();
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        SecureRandom random = new SecureRandom();
        
        byte[] partyUId = Strings.toByteArray("PartyU");
        byte[] partyVId = Strings.toByteArray("PartyV");

        PartyU partyU = new PartyU(random, partyUId, partyVId);

        PartyV partyV = new PartyV(random, partyUId, partyVId);

        System.out.println(Hex.toHexString(
            partyU.doAgreement(partyV.getPublic(),
                        partyV.doStage2(partyU.doStage1()))));
        System.out.println(Hex.toHexString(
            partyV.doAgreement(partyU.getPublic())));
    }
}
