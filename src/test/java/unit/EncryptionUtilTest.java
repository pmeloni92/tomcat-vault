package unit;

import org.apache.tomcat.vault.util.EncryptionUtil;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import static org.junit.Assert.*;

public class EncryptionUtilTest {

    private final String encryptionAlgorithm = "AES";
    private final int keySize = 128;
    private EncryptionUtil eutil = new EncryptionUtil(encryptionAlgorithm, keySize);

    @Test
    public void testValidEncryption() throws Exception {
        
        String data = "Hello, World!";
        byte[] inputData = data.getBytes();
        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();

        
        byte[] encryptedData = eutil.encrypt(inputData, key);

        
        assertNotNull(encryptedData);
        assertFalse(Arrays.equals(inputData, encryptedData));  
    }

    @Test
    public void testNullInputData() throws Exception {
        
        byte[] inputData = null;
        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();

        
        assertThrows(NullPointerException.class, () -> {
            eutil.encrypt(inputData, key);
        });
    }

    @Test
    public void testIllegalArgumentData() throws Exception {
        
        byte[] inputData = null;
        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();

        
        assertThrows(IllegalArgumentException.class, () -> {
            eutil.encrypt(inputData, key);
        });
    }


    @Test
    public void testNullKey() {
        
        String data = "Hello, World!";
        byte[] inputData = data.getBytes();
        SecretKey key = null;

        
        assertThrows(NullPointerException.class, () -> {
            eutil.encrypt(inputData, key);
        });
    }

    @Test
    public void testSuccessfulDecryption() throws Exception {
        
        String originalData = "Hello, World!";
        byte[] originalBytes = originalData.getBytes();

        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), encryptionAlgorithm);

        
        Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedData = cipher.doFinal(originalBytes);

        
        byte[] decryptedData = eutil.decrypt(encryptedData, keySpec);

        
        assertNotNull(decryptedData);
        assertArrayEquals(originalBytes, decryptedData); 
    }

    //for some reason when a null is passed, illegalArgument exeption is thrown instead of nullpointer. Neet to ask coty
    @Test
    public void testNullEncryptedData() throws Exception {
        
        byte[] encryptedData = null;
        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), encryptionAlgorithm);


        
        assertThrows(NullPointerException.class, () -> {
            eutil.decrypt(encryptedData, keySpec);
        });
    }

    @Test
    public void testIncorrectKey() throws Exception {
        
        String originalData = "Hello, World!";
        byte[] originalBytes = originalData.getBytes();

        
        SecretKey correctKey = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec correctKeySpec = new SecretKeySpec(correctKey.getEncoded(), encryptionAlgorithm);

        
        Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, correctKeySpec);
        byte[] encryptedData = cipher.doFinal(originalBytes);

        
        SecretKey incorrectKey = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec incorrectKeySpec = new SecretKeySpec(incorrectKey.getEncoded(), encryptionAlgorithm);


        
        assertThrows(Exception.class, () -> {
            eutil.decrypt(encryptedData, incorrectKeySpec);
        });
    }

    @Test
    public void testEncryptDecryptWithValidData() throws Exception {
        
        String originalData = "Integration Test Data";
        byte[] originalBytes = originalData.getBytes();

        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), encryptionAlgorithm);

        
        byte[] encryptedData = eutil.encrypt(originalBytes, key);
        byte[] decryptedData = eutil.decrypt(encryptedData, keySpec);

        
        assertNotNull(encryptedData);
        assertNotNull(decryptedData);
        assertArrayEquals(originalBytes, decryptedData); 
    }

    @Test
    public void testEncryptDecryptWithIncorrectKey() throws Exception {
        
        String originalData = "Sensitive Information";
        byte[] originalBytes = originalData.getBytes();

        
        SecretKey correctKey = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec correctKeySpec = new SecretKeySpec(correctKey.getEncoded(), encryptionAlgorithm);

        
        SecretKey incorrectKey = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec incorrectKeySpec = new SecretKeySpec(incorrectKey.getEncoded(), encryptionAlgorithm);


        
        byte[] encryptedData = eutil.encrypt(originalBytes, correctKey);

        
        assertThrows(Exception.class, () -> {
            eutil.decrypt(encryptedData, incorrectKeySpec);
        });
    }

    @Test
    public void testEncryptDecryptWithEmptyData() throws Exception {
        
        byte[] emptyData = new byte[0];

        SecretKey key = KeyGenerator.getInstance(encryptionAlgorithm).generateKey();
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), encryptionAlgorithm);

        
        byte[] encryptedData = eutil.encrypt(emptyData, key);
        byte[] decryptedData = eutil.decrypt(encryptedData, keySpec);

        
        assertNotNull(encryptedData);
        assertArrayEquals(emptyData, decryptedData); 
    }

}
