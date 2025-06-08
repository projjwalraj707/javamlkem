package chapter12;


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.CACertsResponse;
import org.bouncycastle.est.CSRRequestResponse;
import org.bouncycastle.est.ESTAuth;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.EnrollmentResponse;
import org.bouncycastle.est.jcajce.JcaHttpAuthBuilder;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.est.jcajce.JsseDefaultHostnameAuthorizer;
import org.bouncycastle.est.jcajce.JsseESTServiceBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;

public class ESTClientExample
{

    /**
     * Grab a set of trust anchors from a URL and return them. Note, we've skipped
     * doing any sort of verification here for the sake of the example. More caution
     * is recommended in real life.
     *
     * @param url the URL pointing at the trust anchor set.
     * @return a set of TrustAnchors based on what was retrieved from the URL.
     */
    public static Set<TrustAnchor> fetchTrustAnchor(String url)
        throws Exception
    {
        CertificateFactory fac = CertificateFactory.getInstance("X509");
        HashSet<TrustAnchor> out = new HashSet<TrustAnchor>();

        InputStream taStream = new URL(url).openStream();
        for (Certificate cert : fac.generateCertificates(taStream))
        {
            out.add(new TrustAnchor((java.security.cert.X509Certificate)cert, null));
        }
        taStream.close();

        return out;
    }

    /**
     * Connect to an EST server and print out it's CA details and CSR Attributes.
     *
     * @param trustAnchors trustAnchors to validate (or not) the connection
     * @param hostName     hostName of the EST server
     * @param portNo       port number to connect on
     */
    public static void listCAsAndCSRAttributes(
        Set<TrustAnchor> trustAnchors, String hostName, int portNo)
        throws ESTException
    {
        String serverRootUrl = hostName + ":" + portNo;

        X509TrustManager[] trustManagers = JcaJceUtils.getCertPathTrustManager(
                                                             trustAnchors, null);

        // Create the service builder
        JsseESTServiceBuilder estBldr = new JsseESTServiceBuilder(
                                                   serverRootUrl, trustManagers);

        // Refuse to match on a "*.com". In the most general case you
        // could use the known suffix list.
        estBldr.withHostNameAuthorizer(
            new JsseDefaultHostnameAuthorizer(Collections.singleton("com")));

        // Build our service object
        ESTService estService = estBldr.build();

        // Fetch and list the CA details
        CACertsResponse csrCerts = estService.getCACerts();

        for (X509CertificateHolder id : csrCerts.getCertificateStore()
                                                        .getMatches(null))
        {
            System.out.println("CA: " + id.getIssuer()
                                      + "[" + id.getSerialNumber() + "]");
        }

        // Fetch and list the CSR attributes
        CSRRequestResponse csrAttributes = estService.getCSRAttributes();

        for (ASN1ObjectIdentifier id : csrAttributes.getAttributesResponse()
                                                            .getRequirements())
        {
            System.out.println("CSR attribute OID: " + id);
        }
    }

    /**
     * Enroll with an EST CA by sending a PKCS#10 certification request with a
     * server that expects HTTPAuth.
     *
     * @param trustAnchors trustAnchors to validate (or not) the connection
     * @param hostName     hostName of the EST server
     * @param portNo       port number to connect on
     * @param userName     user ID to use for connecting
     * @param password     password associated with user ID
     * @param keyPair      the key pair to generate the CSR for
     * @return a Store of the response certificates as X509CertificateHolders
     */
    public static Store<X509CertificateHolder> estEnroll(
        Set<TrustAnchor> trustAnchors,
        String hostName, int portNo,
        String userName, char[] password,
        KeyPair keyPair)
        throws Exception
    {
        // Build our service object
        JsseESTServiceBuilder estBldr = new JsseESTServiceBuilder(
            hostName, portNo, JcaJceUtils.getCertPathTrustManager(
                                                trustAnchors, null));

        estBldr.withHostNameAuthorizer(
            new JsseDefaultHostnameAuthorizer(Collections.singleton("com")));

        ESTService estService = estBldr.build();

        // Create PKCS#10 certification request
        PKCS10CertificationRequestBuilder pkcs10Builder =
            new JcaPKCS10CertificationRequestBuilder(
                        new X500Name("CN=EST Test Client"),
                        keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA384WITHECDSA")
                                      .setProvider("BC").build(keyPair.getPrivate());

        PKCS10CertificationRequest certReq = pkcs10Builder.build(contentSigner);

        // Specify how we will authenticate ourselves
        ESTAuth auth = new JcaHttpAuthBuilder(null, userName, password)
            .setNonceGenerator(new SecureRandom()).setProvider("BC").build();

        // Request the certificate
        boolean isReenroll = false;   // show this is a new enrollment
        EnrollmentResponse enrollmentResponse = estService.simpleEnroll(
                                                            isReenroll, certReq, auth);

        // The enrollment action can be deferred by the server.
        while (!enrollmentResponse.isCompleted())
        {
            Thread.sleep(Math.max(
                1000,
                enrollmentResponse.getNotBefore() - System.currentTimeMillis()));
            enrollmentResponse = estService.simpleEnroll(isReenroll, certReq, auth);
        }

        return enrollmentResponse.getStore();
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());

        Set<TrustAnchor> trustAnchors = fetchTrustAnchor(
                                          "http://testrfc7030.com/dstcax3.pem");

        listCAsAndCSRAttributes(trustAnchors, "testrfc7030.com", 8443);

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("P-384");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Store<X509CertificateHolder> certs = estEnroll(
                                                trustAnchors,
                                                "testrfc7030.com", 8443,
                                                "estuser", "estpwd".toCharArray(),
                                                kp);
        for (X509CertificateHolder cert : certs.getMatches(null))
        {
            System.out.println("Issuer : " + cert.getIssuer()
                                            + "[" + cert.getSerialNumber() + "]");
            System.out.println("Subject: " + cert.getSubject());
        }
    }
}
