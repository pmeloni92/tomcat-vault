import org.apache.tomcat.vault.security.vault.SecurityVault;
import org.apache.tomcat.vault.security.vault.SecurityVaultException;
import org.apache.tomcat.vault.util.PropertyFileManager;
import org.apache.tomcat.vault.util.PropertySourceVault;
import org.jasypt.util.text.BasicTextEncryptor;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class PropertySourceVaultTest {

    @Mock
    private SecurityVault vault;

    @Mock
    private PropertyFileManager pfm;

    @Mock
    private BasicTextEncryptor textEncryptor;

    private PropertySourceVault propertySourceVault;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        propertySourceVault = new PropertySourceVault();
        propertySourceVault.setVault(vault);  // Manually setting the vault
        propertySourceVault.setPropertyFileManager(pfm);  // Manually setting the PropertyFileManager
        propertySourceVault.setTextEncryptor(textEncryptor);  // Manually setting the TextEncryptor
    }

    //Verifies that the vault.init() method is called with the correct parameters during initialization
    @Test
    public void testInitVaultInitialization() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("KEYSTORE_URL", "keystoreUrl");
        properties.setProperty("KEYSTORE_PASSWORD", "keystorePassword");
        when(pfm.load()).thenReturn(properties);

        propertySourceVault.init();

        verify(vault, times(1)).init(any(Map.class));
    }

    //Ensures that no vault initialization happens if properties fail to load.
    @Test
    public void testInitPropertiesLoadFailure() throws Exception {
        when(pfm.load()).thenReturn(null);

        propertySourceVault.init();

        verify(vault, never()).init(any(Map.class));
    }

    //Checks that properties with the VAULT:: prefix are decrypted correctly when the vault is initialized.
    @Test
    public void testGetPropertyWithVaultPrefixSuccess() throws Exception {
        when(vault.isInitialized()).thenReturn(true);
        when(vault.retrieve(anyString(), anyString(), any())).thenReturn("decryptedValue".getBytes());

        String result = propertySourceVault.getProperty("VAULT::alias::password");

        assertEquals("decryptedValue", result);
    }

    //Tests how the class handles a SecurityVaultException when trying to retrieve a vault property.
    @Test
    public void testGetPropertyWithVaultPrefixFailure() throws Exception {
        when(vault.isInitialized()).thenReturn(true);
        when(vault.retrieve(anyString(), anyString(), any())).thenThrow(new SecurityVaultException("Error"));

        String result = propertySourceVault.getProperty("VAULT::alias::password");

        assertNull(result);
    }

    //Verifies that properties with the CRYPT:: prefix are decrypted correctly when the textEncryptor is present.
    @Test
    public void testGetPropertyWithCryptPrefixSuccess() {
        when(textEncryptor.decrypt(anyString())).thenReturn("decryptedText");

        String result = propertySourceVault.getProperty("CRYPT::encryptedText");

        assertEquals("decryptedText", result);
    }

    //Ensures that null is returned when the textEncryptor is not initialized.
    @Test
    public void testGetPropertyWithCryptPrefixWithoutEncryptor() {
        propertySourceVault.setTextEncryptor(null);  // Manually setting textEncryptor to null

        String result = propertySourceVault.getProperty("CRYPT::encryptedText");

        assertNull(result);
    }

    //Checks that properties without a specific prefix are returned unchanged.
    @Test
    public void testGetPropertyWithoutPrefix() {
        String input = "simpleProperty";

        String result = propertySourceVault.getProperty(input);

        assertEquals(input, result);
    }

    //Verifies that properties with the VAULT:: prefix return the original value if the
    //vault is not initialized.
    @Test
    public void testGetPropertyVaultNotInitialized() {
        when(vault.isInitialized()).thenReturn(false);

        String result = propertySourceVault.getProperty("VAULT::alias::password");

        assertEquals("VAULT::alias::password", result);
    }

    //Ensures that the encryption password is correctly set from a system property if provided during initialization.
    @Test
    public void testInitWithEncryptionPasswordFromSystemProperty() throws Exception {
        System.setProperty("org.apache.tomcat.vault.util.ENCRYPTION_PASSWORD", "systemPassword");
        Properties properties = new Properties();
        when(pfm.load()).thenReturn(properties);

        propertySourceVault.init();

        verify(textEncryptor).setPassword("systemPassword");
        System.clearProperty("org.apache.tomcat.vault.util.ENCRYPTION_PASSWORD");
    }

    //hecks that the encryption password is correctly decrypted and set when specified in the loaded properties.
    @Test
    public void testInitWithEncryptionPasswordFromProperties() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("ENCRYPTION_PASSWORD", "CRYPT::encryptedPassword");
        when(pfm.load()).thenReturn(properties);
        when(vault.isInitialized()).thenReturn(true);
        when(vault.retrieve(anyString(), anyString(), any())).thenReturn("decryptedPassword".getBytes());

        propertySourceVault.init();

        verify(textEncryptor).setPassword("decryptedPassword");
    }
}