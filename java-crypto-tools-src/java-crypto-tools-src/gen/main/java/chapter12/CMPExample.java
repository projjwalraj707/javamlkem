package chapter12;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.PBEMacCalculatorProvider;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorProviderBuilder;

/**
 * Basic CMP example.
 */
public class CMPExample
{
    /**
     * Create a MAC protected CMP ProtectedPKIMessage containing a CRMF certification
     * request.
     *
     * @param sender sender of the certification request.
     * @param recipient the target CA address.
     * @param certReqMsg the actual CRMF certification request.
     * @param password the password to use.
     * @return a ProtectedPKIMessage
     */
    public static ProtectedPKIMessage generateMacProtectedMessage(
        X500Name sender, X500Name recipient,
        byte[] senderNonce,
        CertificateRequestMessage certReqMsg,
        char[] password)
        throws CMPException, OperatorCreationException
    {
        MacCalculator pbCalculator = new JcePBMac1CalculatorBuilder(
                      "HmacSHA256", 256).setProvider("BC").build(password);

        return new ProtectedPKIMessageBuilder(
                    new GeneralName(sender), new GeneralName(recipient))
                            .setMessageTime(new Date())
                            .setSenderNonce(senderNonce)
                            .setBody(new PKIBody(
                                PKIBody.TYPE_INIT_REQ,
                                new CertReqMessages(
                                        certReqMsg.toASN1Structure())))
                            .build(pbCalculator);
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("P-384");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, random);
        KeyPair kp = kpg.generateKeyPair();

        BigInteger certReqId = BigInteger.valueOf(System.currentTimeMillis());

        byte[] senderNonce = new byte[16];

        random.nextBytes(senderNonce);

        CertificateRequestMessage certReqMsg = new CertificateRequestMessage(
                CRMFUtils.generateRequestWithPOPSig(
                        kp, new X500Principal("CN=CMP Test Client"),
                        "SHA256withECDSA", certReqId));

        // create the CMP message wrapping the CRMF certification request.
        X500Name sender = new X500Name("CN=Certificate Requester");
        X500Name recipient = new X500Name("CN=Certificate Issuer");

        ProtectedPKIMessage pkiMessage = generateMacProtectedMessage(
            sender, recipient, senderNonce, certReqMsg, "secret".toCharArray());

        PBEMacCalculatorProvider macProvider =
            new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();

        System.out.println("message verified: "
            + pkiMessage.verify(macProvider, "secret".toCharArray()));
    }
}
