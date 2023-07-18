package com.saml.sample;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;

public class CertManager {

//	public static void main(String[] args) {
//
//		try {
//
//			FileInputStream is = new FileInputStream("C:\\Users\\Kiran D. Gaikwad\\Desktop\\DeskTop Files\\myKeyStore2.jks");
//			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
//			String password = "Kiran#1995";
//			char[] passwd = password.toCharArray();
//			keystore.load(is, passwd);
////			Enumeration<String> enumeration = keystore.aliases();
//			//get Alias from KeyStore
////			while(enumeration.hasMoreElements()) {
////	            String alias = enumeration.nextElement();
////	            Certificate certificate = keystore.getCertificate(alias);
////	        }
//			String alias = "kiran.g";
//			// Get certificate of public key
//			Certificate cert = keystore.getCertificate(alias);
//			// Get public key
//			PublicKey publicKey = cert.getPublicKey();
//
//			String publicKeyString = Base64.encodeBase64String(publicKey.getEncoded());
//			System.out.println("Public String ::: "+publicKeyString);
//			
//			Key key = keystore.getKey(alias, passwd);
//			PrivateKey privateKey = (PrivateKey) key;
//			System.out.println("Private String ::: "+privateKey);
//			
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//	}

//		X509Certificate publicKey = 
//		    
//		PrivateKey privateKey = 
//		
//		// create credential and initialize
//		BasicX509Credential credential = new BasicX509Credential();
//		credential.setEntityCertificate(publicKey);
//		credential.setPrivateKey(privateKey);
//	}
	
	/*
	 * To Add X509 Cert in XML
	 * */
	public KeyInfo getKeyInfo(final Credential c, final String keyName) throws SecurityException {

	    final SecurityConfiguration secConfiguration =
	            Configuration.getGlobalSecurityConfiguration();
	    final NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = 
	            secConfiguration.getKeyInfoGeneratorManager();
	    final KeyInfoGeneratorManager keyInfoGeneratorManager =
	            namedKeyInfoGeneratorManager.getDefaultManager();
	    final KeyInfoGeneratorFactory keyInfoGeneratorFactory =
	            keyInfoGeneratorManager.getFactory(c);
	    final KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
	    KeyInfo keyInfo;

	    keyInfo = keyInfoGenerator.generate(c);
//	    KeyInfoHelper.addKeyName(keyInfo,
//	            keyName);
	    return keyInfo;
	}

	/**
	 * gets credential used to sign saml assertionts that are produced. This method
	 * assumes the cert and pkcs formatted primary key are on file system. this data
	 * could be stored elsewhere e.g keystore
	 * 
	 * a credential is used to sign saml response, and includes the private key as
	 * well as a cert for the public key
	 * 
	 * @return
	 * @throws Throwable
	 */
	public Credential getSigningCredential(String publicKeyLocation, String privateKeyLocation) throws Throwable {
		// create public key (cert) portion of credential
		InputStream inStream = new FileInputStream(publicKeyLocation);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate publicKey = (X509Certificate) cf.generateCertificate(inStream);
		inStream.close();

		// create private key
		RandomAccessFile raf = new RandomAccessFile(privateKeyLocation, "r");
		byte[] buf = new byte[(int) raf.length()];
		raf.readFully(buf);
		raf.close();

		PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = kf.generatePrivate(kspec);

		// create credential and initialize
		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(publicKey);
		credential.setPrivateKey(privateKey);
		

		return credential;
	}
}
