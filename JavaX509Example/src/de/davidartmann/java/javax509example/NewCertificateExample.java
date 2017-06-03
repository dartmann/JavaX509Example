package de.davidartmann.java.javax509example;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Use case for creating a X509 certificate with the help of BouncyCastle's
 * {@link X509v3CertificateBuilder}.
 * 
 * @author David Artmann
 *
 */
public class NewCertificateExample {
	
	private static final Logger LOG = Logger.getLogger(NewCertificateExample.class.getSimpleName());

	public static void main(String[] args) {
		/*
		 * First of all we need to add the BouncyCastle provider.
		 */
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		/*
		 * Then we create an X500Name as first necessary parameter of
		 * X509v3CertificateBuilder
		 */
		final X500Name issuer = new X500Name("E=, CN=TestIssuer, O=, OU=, L=, ST=, C=DE");

		/*
		 * Next we create the serial number. In this example it is just a pseudo
		 * random number.
		 */
		BigInteger serialNumber = null;
		try {
			serialNumber = new BigInteger(UUID.randomUUID().toString().getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			LOG.log(Level.WARNING, "The given encoding is wrong", e);
		}

		/*
		 * Followed by creating the start date of our validity period of the
		 * certificate. In this case it should be valid from the moment of
		 * creation.
		 */
		final Date startDate = new Date();

		/*
		 * Of course we need an ending date when the certificate expires. In
		 * this case the certificate should be valid for one year.
		 */
		final Date endDate = new Date(System.currentTimeMillis() + 86400000L * 365);

		/*
		 * The subject is created similar to the issuer as a X500Name.
		 */
		final X500Name subject = new X500Name("E=, CN=TestIssuer, O=, OU=, L=, ST=, C=DE");

		/*
		 * As a last step we need to compute the RSA key pair to given feed the
		 * SubjectPublicKeyInfo with the corresponding public key of the key
		 * pair.
		 */
		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			LOG.log(Level.WARNING, "The given algorithm could not be found", e);
		}
		keyPairGenerator.initialize(4096);
		final KeyPair keyPair = keyPairGenerator.genKeyPair();
		final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo
				.getInstance(keyPair.getPublic().getEncoded());

		/*
		 * Now we can create our certificate builder to create the desired
		 * certificate with this instance.
		 */
		final X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(issuer, serialNumber,
				startDate, endDate, subject, subjectPublicKeyInfo);

		/*
		 * We add the BasicConstraints extension with false, because we want no
		 * CA certificate.
		 */
		try {
			certificateBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
		} catch (CertIOException e) {
			LOG.log(Level.WARNING, "Error while adding the Basic Constraint extension", e);
		}

		/*
		 * Lastly we create the desired certicate as follows.
		 */
		X509Certificate certificate = null;
		try {
			certificate = new JcaX509CertificateConverter()
					.setProvider(BouncyCastleProvider.PROVIDER_NAME)
					.getCertificate(certificateBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
							.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate())));
		} catch (CertificateException | OperatorCreationException e) {
			LOG.log(Level.WARNING, "Error while creating the certificate", e);
		}
		try {
			certificate.checkValidity(new Date());
		} catch (CertificateExpiredException | CertificateNotYetValidException e) {
			LOG.log(Level.WARNING, "Certificate is either not yet valid or already expired", e);
		}
		try {
			certificate.verify(keyPair.getPublic());
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			LOG.log(Level.WARNING, "Error while verifying the certificate", e);
		}

		/*
		 * Printing out result
		 */
		try {
			LOG.info(new String(Base64.getEncoder().encode(certificate.getEncoded()), "UTF-8"));
		} catch (CertificateEncodingException | UnsupportedEncodingException e) {
			LOG.log(Level.WARNING, "Error while encoding the certificate", e);
		}
	}
}
