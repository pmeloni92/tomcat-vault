package unit;

import org.apache.tomcat.vault.util.EncryptionUtil;
import org.apache.tomcat.vault.util.KeyStoreUtil;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyStore;
import java.util.Arrays;

import static org.junit.Assert.*;

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
    public void testValidEncryption() throws Exception {
        // Arrange
        String data = "Hello, World!";
        byte[] inputData = data.getBytes();
        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();

        // Act
        byte[] encryptedData = eutil.encrypt(inputData, key);

        // Assert
        assertNotNull(encryptedData);
        assertFalse(Arrays.equals(inputData, encryptedData));  // Ensure the output is different from the input
    }

    //for some reason when a null is passed, illegalArgument exeption is thrown instead of nullpointer. Neet to ask coty
    @Test
    public void testNullInputData() throws Exception {
        // Arrange
        byte[] inputData = null;
        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();

        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            eutil.encrypt(inputData, key);
        });
    }

    @Test
    public void testIllegalArgumentData() throws Exception {
        // Arrange
        byte[] inputData = null;
        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            eutil.encrypt(inputData, key);
        });
    }


    //after carefully reading the code, this test is not really that smart
    @Test
    public void testNullKey() {
        // Arrange
        String data = "Hello, World!";
        byte[] inputData = data.getBytes();
        SecretKey key = null;

        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            eutil.encrypt(inputData, key);
        });
    }

    @Test
    public void testSuccessfulDecryption() throws Exception {
        // Arrange
        String originalData = "Hello, World!";
        byte[] originalBytes = originalData.getBytes();

        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), encryptionAlgorithm);

        // Encrypt the data first
        Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedData = cipher.doFinal(originalBytes);

        // Act
        byte[] decryptedData = eutil.decrypt(encryptedData, keySpec);

        // Assert
        assertNotNull(decryptedData);
        assertArrayEquals(originalBytes, decryptedData); // Ensure the decrypted data matches the original
    }

    //for some reason when a null is passed, illegalArgument exeption is thrown instead of nullpointer. Neet to ask coty
    @Test
    public void testNullEncryptedData() throws Exception {
        // Arrange
        byte[] encryptedData = null;
        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), encryptionAlgorithm);


        // Act & Assert
        assertThrows(NullPointerException.class, () -> {
            eutil.decrypt(encryptedData, keySpec);
        });
    }

    @Test
    public void testIncorrectKey() throws Exception {
        // Arrange
        String originalData = "Hello, World!";
        byte[] originalBytes = originalData.getBytes();

        // Generate the correct key
        SecretKey correctKey = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec correctKeySpec = new SecretKeySpec(correctKey.getEncoded(), encryptionAlgorithm);

        // Encrypt the data with the correct key
        Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, correctKeySpec);
        byte[] encryptedData = cipher.doFinal(originalBytes);

        // Generate an incorrect key
        SecretKey incorrectKey = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec incorrectKeySpec = new SecretKeySpec(incorrectKey.getEncoded(), encryptionAlgorithm);


        // Act & Assert
        assertThrows(Exception.class, () -> {
            eutil.decrypt(encryptedData, incorrectKeySpec);
        });
    }

}
