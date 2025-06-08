package chapter15;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class WotsExample
{
    private static final String DIGEST = "SHA-256";
    private static final int DIGEST_SIZE = 32;

    private static final int W = 256;
    // CHK_SIZE = floor(log2(DIGEST_SIZE * (W - 1))/log2(W)) + 1
    private static final int CHK_SIZE = 2;
    private static final int KEY_ELEMENTS = W / 8 + CHK_SIZE;

    /**
     * Generate a W-OTS key pair.
     *
     * @param random randomness source for key generation.
     * @return an array in the form of {publicKey, privateKey}
     */
    private static byte[][] computeWotsKeyPair(SecureRandom random)
        throws GeneralSecurityException
    {
        MessageDigest digest = MessageDigest.getInstance(DIGEST);

        // create a 32 * 256 bit private key
        byte[] privateKey = new byte[KEY_ELEMENTS * DIGEST_SIZE];

        random.nextBytes(privateKey);

        byte[] publicKey = new byte[privateKey.length];
        System.arraycopy(privateKey, 0, publicKey, 0, publicKey.length);
        for (int i = 0; i != KEY_ELEMENTS; i++)
        {
            for (int j = 0; j != W; j++)
            {
                digest.update(publicKey, i * DIGEST_SIZE, DIGEST_SIZE);
                digest.digest(publicKey, i * DIGEST_SIZE, DIGEST_SIZE);
            }
        }

        return new byte[][]{publicKey, privateKey};
    }

    /**
     * Calculate a signature based on a digest of the message and the private key.
     *
     * @param privateKey the W-OTS private key to use.
     * @param message the message to be signed.
     * @return the calculated signature.
     */
    private static byte[] computeWotsSignature(byte[] privateKey, byte[] message)
        throws GeneralSecurityException
    {
        MessageDigest digest = MessageDigest.getInstance(DIGEST);

        byte[] msgDigest = digest.digest(message);
        byte[] checkMsg = Arrays.concatenate(msgDigest, calcCheckSum(msgDigest));

        byte[] signature = new byte[privateKey.length];
        System.arraycopy(privateKey, 0, signature, 0, signature.length);
        for (int i = 0; i != KEY_ELEMENTS; i++)
        {
            for (int j = 0; j <= (checkMsg[i] & 0xff); j++)
            {
                digest.update(signature, i * DIGEST_SIZE, DIGEST_SIZE);
                digest.digest(signature, i * DIGEST_SIZE, DIGEST_SIZE);
            }
        }

        return signature;
    }

    /**
     * Calculate a compliment checksum to prevent forgeries based on
     * upping the values of msg[i].
     *
     * @param msg the message to calculate the checksum on.
     * @return the checksum as a byte[].
     */
    private static byte[] calcCheckSum(byte[] msg)
    {
        // compute msg checksum
        int checkSum = 0;
        for (int i = 0; i < msg.length; i++ )
        {
            checkSum += W - 1 - (msg[i] & 0xff);
        }
        // note: this is dependent on CHK_SIZE
        return Pack.shortToBigEndian((short)checkSum);
    }


    /**
     * Verify a passed in W-OTS signature.
     *
     * @param publicKey the W-OTS public key to verify the signature with.
     * @param signature the signature to be verified.
     * @param message the message that the signature should verify.
     * @return true if message verifies, false otherwise.
     */
    private static boolean isVerifiedWotsSignature(
        byte[] publicKey, byte[] signature, byte[] message)
        throws GeneralSecurityException
    {
        MessageDigest digest = MessageDigest.getInstance(DIGEST);

        byte[] msgDigest = digest.digest(message);

        byte[] calcPubKey = new byte[publicKey.length];
        byte[] checkMsg = Arrays.concatenate(msgDigest, calcCheckSum(msgDigest));

        System.arraycopy(signature, 0, calcPubKey, 0, calcPubKey.length);
        for (int i = 0; i != KEY_ELEMENTS; i++)
        {
            for (int j = (checkMsg[i] & 0xff); j != W - 1; j++)
            {
                digest.update(calcPubKey, i * DIGEST_SIZE, DIGEST_SIZE);
                digest.digest(calcPubKey, i * DIGEST_SIZE, DIGEST_SIZE);
            }
        }

        // calcPubKey should now equal publicKey
        return Arrays.constantTimeAreEqual(calcPubKey, publicKey);
    }

    public static void main(String[] args)
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");
        byte[][] wotsKp = computeWotsKeyPair(new SecureRandom());

        byte[] signature = computeWotsSignature(wotsKp[1], msg);

        System.out.println("verifies: "
            + isVerifiedWotsSignature(wotsKp[0], signature, msg));
    }
}
