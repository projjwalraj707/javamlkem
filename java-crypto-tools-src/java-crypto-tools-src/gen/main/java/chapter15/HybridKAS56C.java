package chapter15;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import chapter6.EcUtils;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.HybridValueParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class HybridKAS56C
{
    /**
     * Generate an agreed AES key value of 256 bits in length
     * using both UKM and a T value.
     *
     * @param aPriv Party A's private key.
     * @param bPub Party B's public key.
     * @param tValue T value to create Z || T.
     * @param keyMaterial user keying material to mix with Z || T.
     * @return the generated AES key (256 bits).
     */
    public static SecretKey ecGenerateHybridAESKey(
        PrivateKey aPriv, PublicKey bPub, byte[] tValue, byte[] keyMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement =
            KeyAgreement.getInstance("ECCDHwithSHA256KDF", "BC");

        agreement.init(aPriv, new HybridValueParameterSpec(
                 tValue, new UserKeyingMaterialSpec(keyMaterial)));

        agreement.doPhase(bPub, true);

        return agreement.generateSecret("AES");
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        // PartyU
        KeyPair ecKpU = EcUtils.generateECKeyPair("P-256");

        // PartyV, in this case has a PQC key pair as well.
        KeyPair ecKpV = EcUtils.generateECKeyPair("P-256");
        KeyPair qKpV = KyberKEMExample.kyberGenerateKeyPair(
                           KyberParameterSpec.kyber512);

        // User keying material - shared.
        byte[] ukm = Hex.decode("030f136fa7fef90d185655ed1c6d46bacdb820");

        SecretKeyWithEncapsulation secEncU = KyberKEMExample.kyberGeneratePartyU(
                                                              qKpV.getPublic());

        SecretKey secKeyU = ecGenerateHybridAESKey(
              ecKpU.getPrivate(), ecKpV.getPublic(), secEncU.getEncoded(), ukm);

        SecretKeyWithEncapsulation secEncV = KyberKEMExample.kyberGeneratePartyV(
                                 qKpV.getPrivate(), secEncU.getEncapsulation());

        SecretKey secKeyV = ecGenerateHybridAESKey(
            ecKpV.getPrivate(), ecKpU.getPublic(), secEncV.getEncoded(), ukm);

        System.out.println("U and V Shared Key equal: " +
                Arrays.areEqual(secKeyU.getEncoded(), secKeyV.getEncoded()));
    }
}
