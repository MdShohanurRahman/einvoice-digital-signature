package org.example.sign;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.example.util.AppUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Optional;

public class SignDocument {

    private final X509Certificate certificate;
    private final PrivateKey privateKey;
    private final JsonNode sampleSignNode;

    private final Logger log = LoggerFactory.getLogger(SignDocument.class);
    private final String SAMPLE_SIGN_PATH = "src/main/resources/ublExtension.json";

    public SignDocument(X509Certificate certificate, PrivateKey privateKey) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate not found");
        } else if (privateKey == null) {
            throw new IllegalArgumentException("Private key not found");
        }
        this.sampleSignNode = AppUtils.readJsonFromFile(SAMPLE_SIGN_PATH);
        this.certificate = certificate;
        this.privateKey = privateKey;
    }


    public String sign(String jsonDocument) throws Exception {
        JsonNode jsonNode = AppUtils.readJsonFromString(jsonDocument);
        if (jsonNode == null) {
            throw new RuntimeException("Invalid JSON");
        } else if (certificate == null) {
            throw new RuntimeException("Certificate not found");
        } else if (privateKey == null) {
            throw new RuntimeException("Private key not found");
        }

        /**
         * step 1: create json document and pass as a jsonDocument .
         * see the sample-invoice.json in the src/main/resource folder
         * you json might be different.
         * */

        /**
         * step 2: apply transformation
         * make sure jsonDocument is in utf-8 format and without UBLExtension and Signature
         * see the sample-invoice.json in the src/main/resource folder
         * */

        /**
         * step 3: generate docDigest
         * */
        String docString = Optional
                .ofNullable(AppUtils.minifyJson(jsonDocument))
                .orElseThrow(() -> new IllegalStateException("failed to minify JSON"));
        byte[] docBytes = docString.getBytes(StandardCharsets.UTF_8);
        byte[] docHash = sha256Hash(docBytes);
        String docDigest = encodeBase64(docHash);

        /**
         * step 4: sign the document digest
         * */
        byte[] signHash = signData(docBytes, privateKey);
        String sign = encodeBase64(signHash);

        /**
         * step 5: Generate certificate hash
         * */
        byte[] certHash = getCertHash(certificate);
        String certDigest = encodeBase64(certHash);

        // Get certificate details
        byte[] certificateData = certificate.getEncoded();
        String certData = encodeBase64(certificateData);
        String certSubject = certificate.getSubjectX500Principal().getName();
        String certIssuerName = certificate.getIssuerX500Principal().getName();
        String certSerialNumber = certificate.getSerialNumber().toString();

        // certSubject & certIssuerName might be slightly different value,
        // so please ensure this from your actual certificate,
        // if not match then hard coded the value from your certificate

        // Generate signing time
        String signingTime = generateSigningTime();

        // Access specific nodes from sample-sign json
        JsonNode signatureInformationNode = extractSignatureInformationFromSampleSign();
        JsonNode signatureNode = signatureInformationNode.path("Signature").get(0);
        JsonNode x509DataNode = signatureNode.path("KeyInfo").get(0).path("X509Data").get(0);
        JsonNode qualifyingPropertiesNode = signatureNode
                .path("Object").get(0)
                .path("QualifyingProperties").get(0);

        JsonNode signedSignaturePropertiesNode = qualifyingPropertiesNode
                .path("SignedProperties").get(0)
                .path("SignedSignatureProperties").get(0);

        JsonNode signingCertificateNode = signedSignaturePropertiesNode.path("SigningCertificate").get(0);
        JsonNode certNode = signingCertificateNode.path("Cert").get(0);
        JsonNode certDigestNode = certNode.path("CertDigest").get(0);
        JsonNode issuerSerialNode = certNode.path("IssuerSerial").get(0);

        /**
         * step 6: populate the signed properties section
         * */
        insertNodeValue(certDigestNode.path("DigestValue").get(0), certDigest);
        insertNodeValue(signedSignaturePropertiesNode.path("SigningTime").get(0), signingTime);
        insertNodeValue(issuerSerialNode.path("X509IssuerName").get(0), certIssuerName);
        insertNodeValue(issuerSerialNode.path("X509SerialNumber").get(0), certSerialNumber);

        /**
         * step 7: generate signed properties hash
         * */
        String qualifyingProperties = Optional
                .ofNullable(AppUtils.minifyJson(qualifyingPropertiesNode))
                .orElseThrow(() -> new IllegalStateException("failed to minify JSON"));;
        byte[] qualifyingPropertiesHash = sha256Hash(qualifyingProperties.getBytes(StandardCharsets.UTF_8));
        byte[] propsDigestHash = sha256Hash(qualifyingPropertiesHash);
        String propsDigest = encodeBase64(propsDigestHash);

        /**
         * step 8: populate the information in the document to create the signed document
         * */
        JsonNode x509IssuerSerialNode = x509DataNode.path("X509IssuerSerial").get(0);
        JsonNode referenceNode = signatureNode.path("SignedInfo").get(0).path("Reference");

        insertNodeValue(signatureNode.path("SignatureValue").get(0), sign);
        insertNodeValue(x509DataNode.path("X509Certificate").get(0), certData);
        insertNodeValue(x509DataNode.path("X509SubjectName").get(0), certSubject);
        insertNodeValue(x509IssuerSerialNode.path("X509IssuerName").get(0), certIssuerName);
        insertNodeValue(x509IssuerSerialNode.path("X509SerialNumber").get(0), certSerialNumber);
        insertNodeValue(referenceNode.get(0).path("DigestValue").get(0), propsDigest);
        insertNodeValue(referenceNode.get(1).path("DigestValue").get(0), docDigest);

        /**
         * finally: append the UBLExtensions & Signature in your actual jsonNode
         * */
        ObjectNode invoiceNodeObject = (ObjectNode) jsonNode.path("Invoice").get(0);
        invoiceNodeObject.set("UBLExtensions", sampleSignNode.path("UBLExtensions"));
        invoiceNodeObject.set("Signature", sampleSignNode.path("Signature"));

        System.out.println(encodeBase64(sha256Hash(jsonNode.toString().getBytes())));
        return jsonNode.toPrettyString();
    }

    private byte[] sha256Hash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    private String encodeBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    private byte[] getCertHash(Certificate certificate) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        return messageDigest.digest(certificate.getEncoded());
    }

    private String generateSigningTime() {
        LocalDateTime currentDateTimeUTC = LocalDateTime.now(ZoneOffset.UTC);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");
        return currentDateTimeUTC.format(formatter);
    }

    private void insertNodeValue(JsonNode node, String value) {
        if (node.isObject()) {
            ((ObjectNode) node).put("_", value);
        } else {
            log.warn("Node is not an ObjectNode, cannot insert value.");
        }
    }

    private JsonNode extractSignatureInformationFromSampleSign() {
        JsonNode node = sampleSignNode
                .path("UBLExtensions").get(0)
                .path("UBLExtension").get(0)
                .path("ExtensionContent").get(0)
                .path("UBLDocumentSignatures").get(0)
                .path("SignatureInformation").get(0);;
        if (!node.isMissingNode()) {
            return node;
        } else {
            throw new RuntimeException("SignatureInformation node not found in ublExtension.json");
        }
    }

}
