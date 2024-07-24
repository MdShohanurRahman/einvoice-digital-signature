# Document Signing with Java

## Introduction

This project demonstrates how to document signature creation using Java. You may refer this [link](https://sdk.myinvois.hasil.gov.my/signature-creation/).
The signing process involves creating a digital signature using a private key and a certificate, ensuring the document's integrity and authenticity.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Project Setup](#project-setup)
3. [Generating Keystore and Certificates](#generating-keystore-and-certificates)
4. [Code Explanation](#code-explanation)
    - [Step 1: Create JSON Document](#step-1-create-json-document)
    - [Step 2: Apply Transformation](#step-2-apply-transformation)
    - [Step 3: Generate Document Digest](#step-3-generate-document-digest)
    - [Step 4: Sign the Document Digest](#step-4-sign-the-document-digest)
    - [Step 5: Generate Certificate Hash](#step-5-generate-certificate-hash)
    - [Step 6: Populate Signed Properties](#step-6-populate-signed-properties)
    - [Step 7: Generate Signed Properties Hash](#step-7-generate-signed-properties-hash)
    - [Step 8: Populate Information in Document](#step-8-populate-information-in-document)
5. [Running the Project](#running-the-project)
6. [Conclusion](#conclusion)

## Prerequisites

- JDK 8 or higher
- Maven
- A keystore with a self-signed certificate

## Project Setup

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/document-signing-java.git
    cd document-signing-java
    ```

2. Build the project:
    ```bash
    mvn clean install
    ```

## Generating Keystore and Certificates
For trail certificate you may refer this [link](https://www.msctrustgate.com/assets/pdf_msctrustgate/guide/einvoice/eInvoice_UserGuide_OrganizationCertificate.pdf) for actual certificate.

For self-signed certificate you can follow the following steps. 


1. Generate a keystore and a self-signed certificate using the following command:
    ```bash
    keytool -genkeypair -alias mykey -keyalg RSA -keysize 2048 -validity 365 -keystore mykeystore.jks
    ```

2. Export the certificate:
    ```bash
    keytool -export -alias mykey -keystore mykeystore.jks -rfc -file mycertificate.cer
    ```

3. Import the private key and certificate into the keystore:
    ```bash
    keytool -importkeystore -srckeystore mykeystore.jks -destkeystore mykeystore.jks -srcalias mykey -destalias mykey -srcstoretype jks -deststoretype jks
    ```

## Code Explanation
```java
public class App {
    public static void main( String[] args ) throws Exception {
        String jsonDocumentPath = "src/main/resources/sample-invoice.json";
        String keystorePath = "src/main/resources/mykeystore.jks";
        String keystorePassword = "changeit";
        String alias = "mykey";

        String documentString = new String(Files.readAllBytes(Paths.get(jsonDocumentPath)));
        KeyStore keyStore = AppUtils.getKeyStore(keystorePath, keystorePassword);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keystorePassword.toCharArray());
        SignDocument signDocument = new SignDocument(cert, privateKey);
        String result = signDocument.sign(documentString);
        System.out.println(result);
    }
}

```
You may refer this [code snippet](src/main/java/org/example/sign/SignDocument.java) for details.

```
public String sign(String jsonDocument) throws Exception {
    // method implementation here
}
```

### Step 1: Create JSON Document

Load the JSON document to be signed.

Download Sample Json [here](https://sdk.myinvois.hasil.gov.my/files/sdksamples/1.1-Invoice-Sample.json). 

### Step 2: Apply Transformation

Ensure the JSON document is in UTF-8 format and remove the not required elements [UBLExtension & Signature] if any.

### Step 3: Generate Document Digest

Minify the JSON document and compute the SHA-256 hash of the document.

### Step 4: Sign the Document Digest

Sign the document digest using the private key and generate the signature.

### Step 5: Generate Certificate Hash

Compute the SHA-256 hash of the certificate.

### Step 6: Populate Signed Properties

Populate fields in the JSON document with computed hashes and certificate details.

### Step 7: Generate Signed Properties Hash

Compute the SHA-256 hash of the signed properties.

### Step 8: Populate Information in Document

Insert computed values into the JSON document and complete the signing process.

## Running the Project

1. Ensure you have the keystore (`mykeystore.jks`) and the necessary certificates in place.
2. Run the project:
    ```bash
    mvn spring-boot:run
    ```

## Conclusion

This project provides a comprehensive guide to signing JSON documents using Java. By following the steps outlined, you can ensure the integrity and authenticity of your documents.

---

Feel free to contribute to the project by submitting issues or pull requests. For any questions, contact [your email].

