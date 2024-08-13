package unit;

import org.apache.tomcat.vault.util.EncryptionUtil;
import org.apache.tomcat.vault.util.KeyStoreUtil;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyStore;

public class EncryptionUtilTest {

    private final String encryptionAlgorithm = "AES";
    private final int keySize = 128;
    private EncryptionUtil eutil = new EncryptionUtil(encryptionAlgorithm, keySize);
    private SecretKey adminKey;
    private final String keyStoreAlias = "keyStoreAlias";
    private final char[] keyStorePWD = "keyStorePwd".toCharArray();
    private final String defaultKeystoreType = "JCEKS";
    private final byte[] notEncryptedData = "notEncryptedData".getBytes();

    @Test
    public void encryptTest() throws Exception {
        byte[] encryptedData = encryptTestStringWithTestAuth();
    }

    private byte[] encryptTestStringWithTestAuth() throws Exception {
        SecretKeySpec sKeySpec = getSecretKeySpec();
        return eutil.encrypt(notEncryptedData, sKeySpec);
    }

    private SecretKeySpec getSecretKeySpec() throws Exception {
        KeyStore keystore = KeyStoreUtil.
                createKeyStore(defaultKeystoreType, keyStorePWD);
        KeyStore.Entry e = keystore.getEntry(keyStoreAlias, new KeyStore.PasswordProtection(keyStorePWD));
        adminKey = ((KeyStore.SecretKeyEntry) e).getSecretKey();

        SecretKeySpec sKeySpec = new SecretKeySpec(adminKey.getEncoded(), encryptionAlgorithm);
        return sKeySpec;
    }

    @Test
    public void decryptTest() throws Exception {
        SecretKeySpec sKeySpec = getSecretKeySpec();
        eutil.decrypt(encryptTestStringWithTestAuth(), sKeySpec);
    }
}
