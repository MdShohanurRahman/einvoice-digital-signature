package org.example;

import org.example.sign.SignDocument;
import org.example.util.AppUtils;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

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