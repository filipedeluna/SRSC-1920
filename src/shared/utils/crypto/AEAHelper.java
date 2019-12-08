package shared.utils.crypto;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import shared.errors.crypto.InvalidCertificateInfoException;
import shared.errors.crypto.InvalidSignatureException;
import sun.security.pkcs10.PKCS10;
import sun.security.x509.CertificateValidity;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import org.bouncycastle.asn1.x509.Extension;

import javax.crypto.*;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.security.cert.CertificateEncodingException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public final class AEAHelper {
  private static final long ONE_DAY = 24L * 60L * 60L * 1000L; // 1 year
  private static final String PROVIDER = "BC";

  private RNDHelper random;

  private Cipher cipher;
  private KeyPairGenerator keyPairGenerator;
  private KeyFactory keyFactory;
  private String keyAlg;

  private CertificateFactory certFactory;
  private JcaX509CertificateConverter jcaCertConverter;
  private JcaContentSignerBuilder jcaContentSignBuilder;

  private String certSignAlg;
  private Signature signature;

  // Public Keys ----------------------------------------------------------------------------------------
  public AEAHelper(String keyAlg, String certSignAlg) throws GeneralSecurityException {
    random = new RNDHelper();
    cipher = Cipher.getInstance(keyAlg, PROVIDER);
    keyFactory = KeyFactory.getInstance(keyAlg, PROVIDER);
    keyPairGenerator = KeyPairGenerator.getInstance(keyAlg, PROVIDER);

    certFactory = CertificateFactory.getInstance("X509", PROVIDER);
    signature = Signature.getInstance(certSignAlg, PROVIDER);

    jcaCertConverter = new JcaX509CertificateConverter().setProvider(PROVIDER);
    jcaContentSignBuilder = new JcaContentSignerBuilder(certSignAlg).setProvider(PROVIDER);

    this.certSignAlg = certSignAlg;
    this.keyAlg = keyAlg;
  }

  public PublicKey pubKeyFromBytes(byte[] keyBytes) throws InvalidKeySpecException {
    return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
  }

  public byte[] sign(PrivateKey key, byte[]... data) throws InvalidKeyException, SignatureException {
    signature.initSign(key, new SecureRandom());

    for (byte[] dataPart : data)
      signature.update(dataPart);

    return signature.sign();
  }

  public boolean verifySignature(PublicKey key, byte[] data, byte[] dataSignature) throws InvalidKeyException, SignatureException {
    signature.initVerify(key);

    signature.update(data);

    return signature.verify(dataSignature);
  }

  public byte[] encrypt(byte[] data, Key key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    cipher.init(Cipher.ENCRYPT_MODE, key);

    return cipher.doFinal(data);
  }

  public byte[] decrypt(byte[] data, Key key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    cipher.init(Cipher.DECRYPT_MODE, key);

    return cipher.doFinal(data);
  }

  public KeyPair genKeyPair(int keySize) {
    keyPairGenerator.initialize(keySize);

    return keyPairGenerator.genKeyPair();
  }

  // Certificates --------------------------------------------------------------------------

  public X509Certificate getCertFromBytes(byte[] certBytes) throws CertificateException {
    return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
  }

  public byte[] getCertBytes(X509Certificate certificate) throws java.security.cert.CertificateEncodingException {
    return certificate.getTBSCertificate();
  }

  public String getCertSN(X509Certificate certificate) {
    return certificate.getSerialNumber().toString();
  }

  public X509Certificate getCertFromFile(String file) throws FileNotFoundException, CertificateException {
    return (X509Certificate) certFactory.generateCertificate(new FileInputStream(file));
  }

  public X509Certificate signCert(X509Certificate cert, X509Certificate issuerCert, PrivateKey issuerPrivateKey, int validityDays) throws CertificateException, InvalidCertificateInfoException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    byte[] inCertBytes = cert.getTBSCertificate();
    X509CertInfo info = new X509CertInfo(inCertBytes);

    long now = System.currentTimeMillis();

    try {
      info.set("validity", new CertificateValidity(new Date(now), new Date(now + ONE_DAY * validityDays)));
      info.set(X509CertInfo.ISSUER, issuerCert.getSubjectDN());
    } catch (IOException | CertificateException e) {
      throw new InvalidCertificateInfoException();
    }

    X509CertImpl outCert = new X509CertImpl(info);
    outCert.sign(issuerPrivateKey, issuerCert.getSigAlgName());

    return outCert;
  }

  public PKCS10CertificationRequest csrFromBytes(byte[] csrBytes) throws IOException {
    return new PKCS10CertificationRequest(csrBytes);
  }

  public boolean validate(PublicKey publicKey, X509Certificate certificate) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
    try {
      certificate.verify(publicKey, PROVIDER);
      return true;
    } catch (InvalidKeyException | SignatureException e) {
      return false;
    }
  }

  public X509Certificate convertJavaxCert(javax.security.cert.X509Certificate javaxCert) throws CertificateEncodingException, CertificateException {
    return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(javaxCert.getEncoded()));
  }

  public X509Certificate[] convertJavaxCerts(javax.security.cert.X509Certificate[] javaxCerts) throws CertificateEncodingException, CertificateException {
    X509Certificate[] newCerts = new X509Certificate[javaxCerts.length];

    for (int i = 0; i < javaxCerts.length; i++) {
      newCerts[i] = convertJavaxCert(javaxCerts[i]);
    }

    return newCerts;
  }

  public X509Certificate getCertFromSession(SSLSocket socket) throws SSLPeerUnverifiedException {
    return (X509Certificate) socket.getSession().getPeerCertificates()[0];
  }

  public X509Certificate signCSR(PKCS10CertificationRequest csr, X509Certificate caCert, PrivateKey key, int validityDays) throws InvalidSignatureException, InvalidKeySpecException, CertificateException, IOException, PKCSException, OperatorCreationException {
    // Create content verifier and verify certificate signature is valid
    JcaContentVerifierProviderBuilder cvProvBuilder = new JcaContentVerifierProviderBuilder();
    ContentVerifierProvider cvProvider = cvProvBuilder.build(csr.getSubjectPublicKeyInfo());

    if (!csr.isSignatureValid(cvProvider))
      throw new InvalidSignatureException();

    long now = System.currentTimeMillis();

    PublicKey pubKey = pubKeyFromBytes(csr.getSubjectPublicKeyInfo().getEncoded());

    // Build new cert
    X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
        caCert,
        BigInteger.valueOf(random.getLong(true)),
        new Date(now),
        new Date(now + ONE_DAY * validityDays),
        csr.getSubject(),
        pubKey
    );
    certificateBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        csr.getSubjectPublicKeyInfo()
    );

    // Create content signer and return cert
    ContentSigner contentSigner = jcaContentSignBuilder.build(key);
    return jcaCertConverter.getCertificate(certificateBuilder.build(contentSigner));
  }

  public PKCS10CertificationRequest generateCSR(String name, KeyPair keyPair) throws IOException, CertificateException, SignatureException, InvalidKeyException {
    X500Name x500Name = new X500Name("CN=" + name);

    signature.initSign(keyPair.getPrivate());

    PKCS10 csr = new PKCS10(keyPair.getPublic());
    csr.encodeAndSign(x500Name, signature);
    byte[] csrBytes = csr.getEncoded();

    return new PKCS10CertificationRequest(csrBytes);
  }

  public String getKeyAlg() {
    return keyAlg;
  }

  public String getCertAlg() {
    return certSignAlg;
  }
}
