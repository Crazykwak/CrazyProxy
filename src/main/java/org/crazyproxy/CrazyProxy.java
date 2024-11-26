package org.crazyproxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.*;
import org.crazyproxy.exception.FilePathNullPointException;
import org.crazyproxy.exception.MainConfigNotFoundException;
import org.crazyproxy.exception.SSLContextInitiationException;
import org.crazyproxy.nio.SelectorThread;
import org.crazyproxy.util.Initiator;
import org.yaml.snakeyaml.Yaml;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.util.Map;
import java.util.Properties;

@Slf4j
public class CrazyProxy {

    public static void main(String[] args) {
        MainConfig mainConfig = null;
        String propertyPath = System.getProperty("org.crazyproxy.properties", null);

        Initiator initiator = new Initiator();

        if (propertyPath == null) {
            throw new FilePathNullPointException("propertyPath is null");
        }

        // 기본 설정 세팅
        if (propertyPath.endsWith(".properties")) {
            log.info("Property file fount : properties");
            Properties prop = new Properties();

            try {
                FileInputStream propertyFileInputString = new FileInputStream(propertyPath);
                prop.load(propertyFileInputString);

                String bufferSizeStr = prop.getProperty("bufferSize");
                int bufferSize = initiator.parseBufferSize(bufferSizeStr);

                mainConfig = initiator.getMainConfig(prop, bufferSize);

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else if (propertyPath.endsWith(".yaml") || propertyPath.endsWith(".yml")) {
            log.info("Property file fount : yaml | yml");
            Yaml yaml = new Yaml();
            try {
                Map<String, Object> configMap = yaml.load(new FileInputStream(propertyPath));
                String bufferSizeStr = configMap.get("bufferSize").toString();
                int bufferSize = initiator.parseBufferSize(bufferSizeStr);

                mainConfig = initiator.getMainConfig(configMap, bufferSize);

            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }

        } else if (propertyPath.endsWith(".json")) {
            log.info("Property file fount : Json");
            ObjectMapper mapper = new ObjectMapper();
            try {
                JsonNode jsonNode = mapper.readTree(new File(propertyPath));
                String bufferSizeStr = jsonNode.get("bufferSize").asText();
                int bufferSize = initiator.parseBufferSize(bufferSizeStr);

                mainConfig = initiator.getMainConfig(jsonNode, bufferSize);

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        if (mainConfig == null) {
            throw new MainConfigNotFoundException("mainConfig is null. please check your config file");
        }

        log.info(mainConfig.toString());

        // todo. need worker count and bufferSize setting
        log.info("try to portMap setting");
        final Map<String, SocketInfo> portMap = initiator.initSocketInfoHashMap(mainConfig.getMappingFilePath());
        log.info("portMap setting done.");
        ClientWorkConfig.initInstance(portMap, mainConfig.getWorkerCount(), mainConfig.getBufferSize());

        SSLConfig sslConfig = SSLConfig.getInstance();
        SSLContext sslContext = sslConfig.getContext();
        KeyManager[] keyManagers;
        TrustManager[] trustManagers;

        keyManagers = initiator.getKeyManagers(mainConfig.getKeyFilePath(), mainConfig.getKeyPassword(), mainConfig.getKeyFactoryPassword());
        trustManagers = initiator.getTrustManager(mainConfig.getTrustFilePath(), mainConfig.getTrustPassword());

        try {
            sslContext.init(keyManagers, trustManagers, new SecureRandom());
        } catch (KeyManagementException e) {
            throw new SSLContextInitiationException(e.getMessage());
        }

        SelectorThread selectorThread = new SelectorThread();
        selectorThread.start();

    }
}
