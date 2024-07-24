package org.example.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

public class AppUtils {
    private static final Logger log = LoggerFactory.getLogger(AppUtils.class);
    private static ObjectMapper mapper = new ObjectMapper();

    public static KeyStore getKeyStore(String keyStorePath, String keyStorePassword) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(keyStorePath);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(fileInputStream, keyStorePassword.toCharArray());
        fileInputStream.close();
        return keyStore;
    }

    public static JsonNode readJsonFromFile(String filePath) {
        try {
            return mapper.readTree(new File(filePath));
        } catch (Exception e) {
            log.error("Failed to read json from file: {}", filePath, e);
            return null;
        }
    }

    public static JsonNode readJsonFromString(String json) {
        try {
            return mapper.readTree(json);
        } catch (Exception ex) {
            log.error("Failed to parse json from file: {}", json, ex);
            return null;
        }
    }

    public static String minifyJson(JsonNode json) {
        try {
            return mapper.writeValueAsString(json);
        } catch (Exception ex) {
            log.error("Failed to minify json : {}", json, ex);
            return null;
        }
    }

    public static String minifyJson(String json) {
        try {
            return mapper.writeValueAsString(json);
        } catch (Exception ex) {
            log.error("Failed to minify json : {}", json, ex);
            return null;
        }
    }
}