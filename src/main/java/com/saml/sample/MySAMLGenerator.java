package com.saml.sample;

import java.io.IOException;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
//import org.opensaml.Configuration;
//import org.opensaml.xml.XMLObject;
//import org.opensaml.xml.io.Marshaller;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.fasterxml.jackson.databind.ObjectMapper;

public class MySAMLGenerator {

	public static void main(String[] args)
			throws org.opensaml.security.SecurityException, TransformerFactoryConfigurationError, TransformerException,
			IOException, ParserConfigurationException, MarshallingException{
		EntityDescriptorBuilder entityDescriptorBuilder = new EntityDescriptorBuilder();
		EntityDescriptor spEntityDescriptor = entityDescriptorBuilder.buildObject();

		spEntityDescriptor.setEntityID("ABCD");
		SPSSODescriptorBuilder sPSSODescriptorBuilder = new SPSSODescriptorBuilder();
		SPSSODescriptor spSSODescriptor = sPSSODescriptorBuilder.buildObject(); 

		spSSODescriptor.setWantAssertionsSigned(true);
		spSSODescriptor.setAuthnRequestsSigned(true);

//		X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
//		keyInfoGeneratorFactory.setEmitEntityCertificate(true);
//		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

		KeyDescriptorBuilder keyDescriptorBuilder = new KeyDescriptorBuilder();
		KeyDescriptor encKeyDescriptor = keyDescriptorBuilder.buildObject();

		encKeyDescriptor.setUse(UsageType.ENCRYPTION); // Set usage

		Credential X509Credential = null;
		// Generating key info. The element will contain the public key. The key is used
		// to by the IDP to encrypt data
//		try {
//			encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(X509Credential));
//		} catch (SecurityException e) {
//			System.out.println();
//		}

		spSSODescriptor.getKeyDescriptors().add(encKeyDescriptor);

		KeyDescriptor signKeyDescriptor = keyDescriptorBuilder.buildObject();

		signKeyDescriptor.setUse(UsageType.SIGNING); // Set usage

		// Generating key info. The element will contain the public key. The key is used
		// to by the IDP to verify signatures
//		try {
//			signKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(X509Credential));
//		} catch (SecurityException e) {
//			System.out.println("Error " + e);
//		}

		spSSODescriptor.getKeyDescriptors().add(signKeyDescriptor);

		// Request transient pseudonym
		NameIDFormatBuilder nameIdFormatBuilder = new NameIDFormatBuilder();
		NameIDFormat nameIDFormat = nameIdFormatBuilder.buildObject();
		nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
		spSSODescriptor.getNameIDFormats().add(nameIDFormat);

		AssertionConsumerServiceBuilder assertionBuilder = new AssertionConsumerServiceBuilder();
		AssertionConsumerService assertionConsumerService = assertionBuilder.buildObject();
		
		assertionConsumerService.setIndex(0);
		assertionConsumerService.setBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

		// Setting address for our AssertionConsumerService
		assertionConsumerService.setLocation("");
		spSSODescriptor.getAssertionConsumerServices().add(assertionConsumerService);

		// Finally

		spSSODescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

		spEntityDescriptor.getRoleDescriptors().add(spSSODescriptor);
		
		ObjectMapper obj = new ObjectMapper();
		String printIt= obj.writeValueAsString(spEntityDescriptor);
		System.out.println("PrinIT ::: "+printIt);

		DocumentBuilder builder;
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

		builder = factory.newDocumentBuilder();
		Document document = builder.newDocument();
//		ResponseMarshaller marshaller = new ResponseMarshaller();
//		Element element = marshaller.marshall(spEntityDescriptor);
//		Marshaller out =Configuration.getMarshallerFactory().getMarshaller((QName) spEntityDescriptor);
//		out.marshall((XMLObject) spEntityDescriptor, document);

		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		StringWriter stringWriter = new StringWriter();
		StreamResult streamResult = new StreamResult(stringWriter);
		DOMSource source = new DOMSource(document);
		transformer.transform(source, streamResult);
		stringWriter.close();
		String metadataXML = stringWriter.toString();
		System.out.println("metadata XML :: "+metadataXML);
	}
}
