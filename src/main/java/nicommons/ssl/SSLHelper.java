package nicommons.ssl;

import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SSL connections utilities
 */
public class SSLHelper {

    private static final Logger LOG = LoggerFactory.getLogger(SSLHelper.class);



    /**
     * Builds a keystore from a file.
     * 
     * @param url
     *            URL to the keystore file
     * @param password
     *            Keystore password
     * @param keystoreType
     *            Keystore type (cf <a href=
     *            "http://docs.oracle.com/javase/1.4.2/docs/guide/security/CryptoSpec.html#AppA" >Appendix A in the Java
     *            Cryptography Architecture API Specification & Reference</a>)
     */
    public static KeyStore createKeyStore(final URL url, final String password, final String keystoreType)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        if (url == null) {
            throw new IllegalArgumentException("Keystore url may not be null");
        }
        LOG.debug("Initializing key store : " + url + " (type " + keystoreType + ")");
        KeyStore keystore = KeyStore.getInstance(keystoreType);
        keystore.load(url.openStream(), password != null ? password.toCharArray() : null);
        return keystore;
    }



    /**
     * Builds a list of {@link KeyManager} from the default {@link KeyManagerFactory}.
     * 
     * @param keystore
     *            The keystore that holds certificats
     * @param password
     *            Keystore password
     * @see KeyManagerFactory#getKeyManagers()
     * @see KeyManagerFactory#getInstance(String)
     * @see KeyManagerFactory#getDefaultAlgorithm()
     */
    public static KeyManager[] createKeyManagers(final KeyStore keystore, final String password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (keystore == null) {
            throw new IllegalArgumentException("Keystore may not be null");
        }
        LOG.debug("Initializing key manager");
        KeyManagerFactory kmfactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmfactory.init(keystore, password != null ? password.toCharArray() : null);
        return kmfactory.getKeyManagers();
    }



    /**
     * Builds a list of {@link TrustManager} from the default {@link TrustManagerFactory}.
     * 
     * @param keystore
     *            Le keystore contenant les certificats
     * @see TrustManagerFactory#getInstance(String)
     * @see TrustManagerFactory#getTrustManagers()
     */
    public static TrustManager[] createTrustManagers(final KeyStore keystore) throws KeyStoreException,
            NoSuchAlgorithmException {
        if (keystore == null) {
            throw new IllegalArgumentException("Keystore may not be null");
        }
        LOG.debug("Initializing trust manager");
        TrustManagerFactory tmfactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmfactory.init(keystore);
        TrustManager[] trustmanagers = tmfactory.getTrustManagers();
        for (int i = 0; i < trustmanagers.length; i++) {
            if (trustmanagers[i] instanceof X509TrustManager) {
                trustmanagers[i] = trustmanagers[i];
            }
        }
        return trustmanagers;
    }

}