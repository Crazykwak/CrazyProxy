package org.crazyproxy;

import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.*;
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
            throw new RuntimeException("propertyPath is null");
        }

        if (propertyPath.endsWith(".properties")) {
            Properties prop = new Properties();

            try {
                FileInputStream propertyFileInputString = new FileInputStream(propertyPath);
                prop.load(propertyFileInputString);

                String bufferSizeStr = prop.getProperty("bufferSize");
                int bufferSize = initiator.parseBufferSize(bufferSizeStr);

                mainConfig = initiator.getMainConfig(mainConfig, prop, bufferSize);

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else if (propertyPath.endsWith(".yaml") || propertyPath.endsWith(".yml")) {
            Yaml yaml = new Yaml();
            try {
                Map<String, Object> configMap = yaml.load(new FileInputStream(propertyPath));
                String bufferSizeStr = configMap.get("bufferSize").toString();
                int bufferSize = initiator.parseBufferSize(bufferSizeStr);

                mainConfig = initiator.getMainConfig(mainConfig, configMap, bufferSize);


            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }

        } else if (propertyPath.endsWith(".xml")) {
            // todo. xml load
        } else if (propertyPath.endsWith(".json")) {
            // todo. json load
        }

        if (mainConfig == null) {
            throw new RuntimeException("mainConfig is null");
        }

        log.info(mainConfig.toString());

        // todo. need worker count and bufferSize setting
        log.info("try to portMap setting");
        final Map<String, SocketInfo> portMap = initiator.initSocketInfoHashMap(mainConfig.mappingFilePath());
        log.info("portMap setting done.");
        ClientWorkConfig.initInstance(portMap, mainConfig.workerCount(), mainConfig.bufferSize());

        SSLConfig sslConfig = SSLConfig.getInstance();
        SSLContext sslContext = sslConfig.getContext();
        KeyManager[] keyManagers;
        TrustManager[] trustManagers;

        keyManagers = initiator.getKeyManagers(mainConfig.keyFilePath(), mainConfig.keyPassword(), mainConfig.keyFactoryPassword());
        trustManagers = initiator.getTrustManager(mainConfig.trustFilePath(), mainConfig.trustPassword());

        try {
            sslContext.init(keyManagers, trustManagers, new SecureRandom());
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }

        SelectorThread selectorThread = new SelectorThread();
        selectorThread.start();

    }
}
