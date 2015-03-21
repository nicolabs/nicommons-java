package nicommons.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * From "Apache commons HttpClient contrib"
 * 
 * @see <a
 *      href="http://hc.apache.org/httpclient-3.x/sslguide.html">http://hc.apache.org/httpclient-3.x/sslguide.html</a>
 * @see <a
 *      href="http://svn.apache.org/viewvc/httpcomponents/oac.hc3x/trunk/src/contrib/org/apache/commons/httpclient/contrib/ssl/AuthSSLProtocolSocketFactory.java?view=markup">AuthSSLProtocolSocketFactory.java</a>
 */
public class ClientAndServerAuthSSLSocketFactory implements SecureProtocolSocketFactory {

    private static final Logger LOG                = LoggerFactory.getLogger(ClientAndServerAuthSSLSocketFactory.class);

    private URL                 keystoreUrl        = null;

    private String              keystorePassword   = null;

    private final String        keystoreType;

    private URL                 truststoreUrl      = null;

    private String              truststorePassword = null;

    private final String        truststoreType;

    private SSLContext          sslcontext         = null;

    public KeyManager[]         keymanagers;

    public TrustManager[]       trustmanagers;



    /**
     * Either a keystore or truststore file must be given. Otherwise SSL context initialization error will result.
     * 
     * @param keystoreUrl
     *            URL of the keystore file. May be <tt>null</tt> if HTTPS client authentication is not to be used.
     * @param keystorePassword
     *            Password to unlock the keystore. IMPORTANT: this implementation assumes that the same password is used
     *            to protect the key and the keystore itself.
     * @param keystoreType
     *            Keystore type (format) (e.g. : "JKS", "PKCS12")
     * @param truststoreUrl
     *            URL of the truststore file. May be <tt>null</tt> if HTTPS server authentication is not to be used.
     * @param truststoreType
     *            Password to unlock the truststore.
     * @param keyStoreType
     *            Truststore type (format) (e.g. : "JKS", "PKCS12")
     */
    public ClientAndServerAuthSSLSocketFactory(final URL keystoreUrl, final String keystorePassword,
            final String keystoreType, final URL truststoreUrl, final String truststorePassword,
            final String truststoreType) {
        super();
        this.keystoreUrl = keystoreUrl;
        this.keystorePassword = keystorePassword;
        this.keystoreType = keystoreType;
        this.truststoreUrl = truststoreUrl;
        this.truststorePassword = truststorePassword;
        this.truststoreType = truststoreType;
    }



    private SSLContext getSSLContext() throws IOException, UnsupportedOperationException {
        if (this.sslcontext == null) {
            this.sslcontext = createSSLContext();
        }
        return this.sslcontext;
    }



    private SSLContext createSSLContext() throws IOException, UnsupportedOperationException {
        try {
            KeyManager[] keymanagers = null;
            TrustManager[] trustmanagers = null;
            if (this.keystoreUrl != null) {
                KeyStore keystore = SSLHelper
                        .createKeyStore(this.keystoreUrl, this.keystorePassword, this.keystoreType);
                if (LOG.isDebugEnabled()) {
                    Enumeration aliases = keystore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = (String) aliases.nextElement();
                        Certificate[] certs = keystore.getCertificateChain(alias);
                        if (certs != null) {
                            LOG.debug("Certificate chain '" + alias + "':");
                            for (int c = 0; c < certs.length; c++) {
                                if (certs[c] instanceof X509Certificate) {
                                    X509Certificate cert = (X509Certificate) certs[c];
                                    LOG.debug(" Certificate " + (c + 1) + ":");
                                    LOG.debug("  Subject DN: " + cert.getSubjectDN());
                                    LOG.debug("  Signature Algorithm: " + cert.getSigAlgName());
                                    LOG.debug("  Valid from: " + cert.getNotBefore());
                                    LOG.debug("  Valid until: " + cert.getNotAfter());
                                    LOG.debug("  Issuer: " + cert.getIssuerDN());
                                }
                            }
                        }
                    }
                }
                keymanagers = SSLHelper.createKeyManagers(keystore, this.keystorePassword);
                this.keymanagers = keymanagers;
            }
            if (this.truststoreUrl != null) {
                KeyStore keystore = SSLHelper.createKeyStore(this.truststoreUrl, this.truststorePassword,
                        this.truststoreType);
                if (LOG.isDebugEnabled()) {
                    Enumeration aliases = keystore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = (String) aliases.nextElement();
                        LOG.debug("Trusted certificate '" + alias + "':");
                        Certificate trustedcert = keystore.getCertificate(alias);
                        if (trustedcert != null && trustedcert instanceof X509Certificate) {
                            X509Certificate cert = (X509Certificate) trustedcert;
                            LOG.debug("  Subject DN: " + cert.getSubjectDN());
                            LOG.debug("  Signature Algorithm: " + cert.getSigAlgName());
                            LOG.debug("  Valid from: " + cert.getNotBefore());
                            LOG.debug("  Valid until: " + cert.getNotAfter());
                            LOG.debug("  Issuer: " + cert.getIssuerDN());
                        }
                    }
                }
                trustmanagers = SSLHelper.createTrustManagers(keystore);
                this.trustmanagers = trustmanagers;
            }
            SSLContext sslcontext = SSLContext.getInstance("TLS");
            sslcontext.init(keymanagers, trustmanagers, null);
            return sslcontext;
        } catch (IOException e) {
            LOG.error("An I/O error occured while reading a keystore", e);
            throw e;
        } catch (Exception e) {
            LOG.error("Could not initialize a SSL context", e);
            throw new UnsupportedOperationException(e);
        }
    }



    /**
     * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int,java.net.InetAddress,int)
     */
    @Override
    public Socket createSocket(String host, int port, InetAddress clientHost, int clientPort) throws IOException,
            UnknownHostException, UnsupportedOperationException {
        return getSSLContext().getSocketFactory().createSocket(host, port, clientHost, clientPort);
    }



    /**
     * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int)
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException,
            UnsupportedOperationException {
        return getSSLContext().getSocketFactory().createSocket(host, port);
    }



    /**
     * @see SecureProtocolSocketFactory#createSocket(java.net.Socket,java.lang.String,int,boolean)
     */
    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException,
            UnknownHostException, UnsupportedOperationException {
        return getSSLContext().getSocketFactory().createSocket(socket, host, port, autoClose);
    }



    @Override
    public Socket createSocket(final String host, final int port, final InetAddress localAddress, final int localPort,
            final HttpConnectionParams params) throws IOException, UnknownHostException, ConnectTimeoutException,
            UnsupportedOperationException {
        // TODO ? use HttpConnectionParams ?
        return getSSLContext().getSocketFactory().createSocket(host, port, localAddress, localPort);
    }

}