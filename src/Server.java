/*
Copyright © 2016-2017 Leejae Karinja

This file is part of Java HTTPS Server.

Java HTTPS Server is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Java HTTPS Server is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Java HTTPS Server.  If not, see <http://www.gnu.org/licenses/>.
*/

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

public class Server {

	//READ ME http://stackoverflow.com/questions/26828649/diffiehellman-key-exchange-to-aes-or-desede-in-java

	private static int port = 13579;
	private static byte[] nonce;
	private static byte[] keyData;

	private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static final String SIGNATURE_ALGORITHM = "SHA512withECDSA";
	private static final String KEY_GENERATION_ALGORITHM = "ECDH";//"ECDH";
	private static final String SSL_CONTEXT = "TLSv1.2";
	private static final String KEY_STORE_INSTANCE = "JKS";
	private static final String KMF_INSTANCE = "SunX509";
	private static final Date BEFORE = new Date(System.currentTimeMillis() - 5000);
	private static final Date AFTER = new Date(System.currentTimeMillis() + 600000);

	static class Handler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			String response = "This is a test!";
			System.out.println("Handler");
			exchange.sendResponseHeaders(200, response.length());
			OutputStream os = exchange.getResponseBody();
			os.write(response.getBytes());
			os.close();
		}

	}

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {

		try {
			genNonce();
			genKeystore();

			InetSocketAddress address = new InetSocketAddress(port);

			KeyStore ks = KeyStore.getInstance(KEY_STORE_INSTANCE);
			ks.load(new ByteArrayInputStream(keyData), (new String(nonce).toCharArray()));

			Certificate cert = ks.getCertificate("foo.bar");
			System.out.println(cert);

			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KMF_INSTANCE);
			kmf.init(ks, (new String(nonce).toCharArray()));

			SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT);
			sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

			HttpsServer httpsServer = HttpsServer.create(address, 5);

			httpsServer.createContext("/", new Handler());

			httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {

				public void configure(HttpsParameters params) {
					try {
						System.out.println("Configure...");
						System.out.println(params.getClientAddress().getHostName());
						SSLContext c = SSLContext.getDefault();
						SSLEngine engine = c.createSSLEngine();
						params.setNeedClientAuth(false);
						params.setCipherSuites(engine.getEnabledCipherSuites());
						params.setProtocols(engine.getEnabledProtocols());
						SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
						params.setSSLParameters(defaultSSLParameters);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			});
			httpsServer.setExecutor(null);
			httpsServer.start();
			System.out.println("Start...");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Generates a one time use secure random number to be used as the password
	 * for a keystore
	 * 
	 * @return Returns void on completion
	 */
	private static void genNonce() {
		SecureRandom rand = new SecureRandom();
		nonce = new byte[2048];
		rand.nextBytes(nonce);
		return;
	}

	/**
	 * Generates a one time use keystore for use with an SSL session
	 * 
	 * @return Returns void on completion
	 */
	private static void genKeystore() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_GENERATION_ALGORITHM);//, PROVIDER_NAME);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			X509Certificate cert = createCACert(keyPair.getPublic(), keyPair.getPrivate());

			KeyStore ks = KeyStore.getInstance(KEY_STORE_INSTANCE);
			ks.load(null, (new String(nonce)).toCharArray());
			ks.setKeyEntry("foo.bar", keyPair.getPrivate(), (new String(nonce)).toCharArray(), new java.security.cert.Certificate[] { cert });
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			ks.store(os, (new String(nonce)).toCharArray());
			keyData = os.toByteArray();
			os.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}

	/**
	 * Create a certificate to use by a Certificate Authority
	 * Retrieved from
	 * http://www.programcreek.com/java-api-examples/index.php?class
	 * =org.bouncycastle.cert.X509v3CertificateBuilder&method=addExtension
	 * 
	 * @param publicKey Public key
	 * @param privateKey Private key
	 * @return Generated X509 Certificate
	 */
	private static X509Certificate createCACert(PublicKey publicKey, PrivateKey privateKey) throws Exception {
		X500Name issuerName = new X500Name("CN=127.0.0.1, O=FOO, L=BAR, ST=BAZ, C=QUX");

		X500Name subjectName = issuerName;

		BigInteger serial = BigInteger.valueOf(new SecureRandom().nextInt());

		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, BEFORE, AFTER, subjectName, publicKey);
		builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey));
		builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

		KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
		builder.addExtension(Extension.keyUsage, false, usage);

		ASN1EncodableVector purposes = new ASN1EncodableVector();
		purposes.add(KeyPurposeId.id_kp_serverAuth);
		purposes.add(KeyPurposeId.id_kp_clientAuth);
		purposes.add(KeyPurposeId.anyExtendedKeyUsage);
		builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

		X509Certificate cert = signCertificate(builder, privateKey);
		cert.checkValidity(new Date());
		cert.verify(publicKey);

		return cert;
	}

	/**
	 * Helper method
	 * Retrieved from
	 * http://www.programcreek.com/java-api-examples/index.php?api
	 * =org.bouncycastle.cert.bc.BcX509ExtensionUtils
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) throws Exception {
		ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(key.getEncoded()));
		ASN1Sequence seq = (ASN1Sequence) is.readObject();
		is.close();
		@SuppressWarnings("deprecation")
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(seq);
		return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
	}

	/**
	 * Helper method
	 * Retrieved from
	 * http://www.programcreek.com/java-api-examples/index.php?source_dir
	 * =mockserver-master/mockserver-core/src/main/java/org/mockserver/socket/
	 * KeyStoreFactory.java
	 * 
	 * @param certificateBuilder
	 * @param signedWithPrivateKey
	 * @return
	 * @throws Exception
	 */
	private static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey signedWithPrivateKey) throws Exception {
		ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build(signedWithPrivateKey);
		return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateBuilder.build(signer));
	}

}
