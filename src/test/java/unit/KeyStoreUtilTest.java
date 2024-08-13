package unit;

import org.apache.tomcat.vault.util.KeyStoreUtil;
import org.junit.Test;

public class KeyStoreUtilTest {

    private String keyStoreType = "JCEKS";
    private char[] keyStorePWD = "keystorePWD".toCharArray();

    @Test
    public void createKeyStoreTest() throws Exception{
        KeyStoreUtil.createKeyStore(keyStoreType, keyStorePWD);
    }
}
