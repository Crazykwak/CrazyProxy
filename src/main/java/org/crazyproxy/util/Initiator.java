package org.crazyproxy.util;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.MainConfig;
import org.crazyproxy.config.SSLKeyInfo;
import org.crazyproxy.config.SocketInfo;
import org.crazyproxy.ssl.AllTrustManager;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@Slf4j
public class Initiator {

    private String getStringValue(Object value) {
        return value == null ? null : value.toString();
    }

    private Integer getIntValue(Object value, int defaultValue) {
        return value == null ? defaultValue : Integer.parseInt(value.toString());
    }

    private MainConfig buildMainConfig(MainConfig.MainConfigBuilder builder, int bufferSize) {
        return builder
                .bufferSize(bufferSize)
                .build();
    }

    public MainConfig getMainConfig(Map<String, Object> configMap, int bufferSize) {
        MainConfig.MainConfigBuilder builder = MainConfig.builder()
                .keyFilePath(getStringValue(configMap.get("keyFilePath")))
                .keyPassword(getStringValue(configMap.get("keyPassword")))
                .keyFactoryPassword(getStringValue(configMap.get("keyFactoryPassword")))
                .trustFilePath(getStringValue(configMap.get("trustFilePath")))
                .trustPassword(getStringValue(configMap.get("trustPassword")))
                .mappingFilePath(configMap.get("mappingFilePath").toString())
                .workerCount(getIntValue(configMap.get("workerCount"), 50));

        return buildMainConfig(builder, bufferSize);
    }

    public MainConfig getMainConfig(Properties prop, int bufferSize) {
        MainConfig.MainConfigBuilder builder = MainConfig.builder()
                .keyFilePath(prop.getProperty("keyFilePath"))
                .keyPassword(prop.getProperty("keyPassword"))
                .keyFactoryPassword(prop.getProperty("keyFactoryPassword"))
                .trustFilePath(prop.getProperty("trustFilePath"))
                .trustPassword(prop.getProperty("trustPassword"))
                .mappingFilePath(prop.getProperty("mappingFilePath"))
                .workerCount(Integer.parseInt(prop.getProperty("workerCount", "50")));

        return buildMainConfig(builder, bufferSize);
    }

    public MainConfig getMainConfig(JsonNode jsonNode, int bufferSize) {
        MainConfig.MainConfigBuilder builder = MainConfig.builder()
                .keyFilePath(getStringValue(jsonNode.get("keyFilePath")))
                .keyPassword(getStringValue(jsonNode.get("keyPassword")))
                .keyFactoryPassword(getStringValue(jsonNode.get("keyFactoryPassword")))
                .trustFilePath(getStringValue(jsonNode.get("trustFilePath")))
                .trustPassword(getStringValue(jsonNode.get("trustPassword")))
                .mappingFilePath(jsonNode.get("mappingFilePath").asText())
                .workerCount(jsonNode.has("workerCount") ? jsonNode.get("workerCount").asInt() : 50);

        return buildMainConfig(builder, bufferSize);
    }

    public int parseBufferSize(String bufferSizeStr) {
        if (bufferSizeStr == null || bufferSizeStr.isEmpty()) {
            return 1024 * 100; // 기본값 100KB
        }

        bufferSizeStr = bufferSizeStr.trim().toLowerCase();

        try {
            if (bufferSizeStr.endsWith("kb")) {
                return Integer.parseInt(bufferSizeStr.replace("kb", "").trim()) * 1024;
            } else if (bufferSizeStr.endsWith("mb")) {
                return Integer.parseInt(bufferSizeStr.replace("mb", "").trim()) * 1024 * 1024;
            } else {
                // 단위가 없으면 byte로 처리
                return Integer.parseInt(bufferSizeStr);
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid buffer size format: " + bufferSizeStr, e);
        }
    }

    /**
     * Create SSL KeyManager. if -D option org.crazyproxy.keyFilePath is null then keymanager is null
     * @return KeyManager[] for SSLContext
     */
    public KeyManager[] getKeyManagers(String keyFilePath, String keyPassword, String keyFactoryPassword) {

        File keyFile = null;
        KeyManager[] keyManagers = null;
        if (keyFilePath != null) {
            keyFile = new File(keyFilePath);
        }

        SSLKeyInfo sslKeyInfo;
        // 키 파일 여부 확인. 없으면 null로 실행
        if (keyFile != null && keyFile.exists()) {
            log.info("Key file exists. try to set SSL Key");
            sslKeyInfo = setSSLKeyInfo(keyFilePath, keyPassword, keyFactoryPassword);
            keyManagers = sslKeyInfo.getKeyManagerFactory().getKeyManagers();
            log.info("Key set done.");
        }
        return keyManagers;
    }

    /**
     * create TrustManager. if -D option org.crazyproxy.trustedCert is null then All Trust Manager class is available
     * @return TrustManager[] for SSLContext
     */
    public TrustManager[] getTrustManager(String trustFilePath, String trustPassword) {
        // null이면 AllTrustManager 객체 생성. 모든 인증서를 ㅇㅋㅇㅋ 하는 친구
        if (trustFilePath != null) {
            log.info("Trusted certificate exists. try to set SSL Trust");
            File trustedCertFile = new File(trustFilePath);
            return createTrustManager(trustedCertFile, trustPassword);
        }

        return new TrustManager[]{new AllTrustManager()};
    }

    /**
     * set SSL Key Info. if org.crazyproxy.keyFilePath is not null. active this method
     */
    protected SSLKeyInfo setSSLKeyInfo(String keyFilePath, String keyStorePassword, String keyManagerFactoryPassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            FileInputStream keyStoreStream = new FileInputStream(keyFilePath);
            keyStore.load(keyStoreStream, keyStorePassword.toCharArray());
            keyStoreStream.close();
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyManagerFactoryPassword.toCharArray());
            SSLKeyInfo.initInstance(keyManagerFactory);
            return SSLKeyInfo.getInstance();
        } catch (FileNotFoundException e) {
            log.error("Key file not found. keyFilePath = {}", keyFilePath);
            throw new RuntimeException(e);
        } catch (CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException |
                 KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * this method is TrustManger creator. if org.crazyproxy.trustedCert is not null. active this method
     */
    protected TrustManager[] createTrustManager(File trustedCertFile, String keystorePassword) {
        InputStream trustStoreIS = null;
        KeyStore trustStore = null;
        if (trustedCertFile != null && trustedCertFile.exists()) {
            try {
                trustStore = KeyStore.getInstance("JKS");
                trustStoreIS = new FileInputStream(trustedCertFile.getAbsolutePath());
                trustStore.load(trustStoreIS, keystorePassword.toCharArray());
                trustStoreIS.close();
            } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
                throw new RuntimeException(e);
            } finally {
                if (trustStoreIS != null) {
                    try {
                        trustStoreIS.close();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }

        TrustManagerFactory trustFactory;
        try {
            trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            log.info("trustStore = {}", trustStore);
            trustFactory.init(trustStore);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        return trustFactory.getTrustManagers();

    }

    /**
     * Initiate for Port forwarding HashMap. you must set mapping.properties file.
     * todo. URI 클래스를 활용해도 괜찮을 듯.
     */
    public Map<String, SocketInfo> initSocketInfoHashMap(String mappingFilePath) {
        final Map<String, SocketInfo> portMap = new HashMap<>();

        FileInputStream fis;
        try {
            // todo. file address must inject by option.
            fis = new FileInputStream(mappingFilePath);
            Properties properties = new Properties();
            properties.load(fis);
            fis.close();

            for (Object key : properties.keySet()) {
                String port = (String) key;
                String host = properties.get(port).toString();
                String path = "/";
                boolean isHttps = false;
                int targetPort = 80;

                // 일단 https, http 여부 부터 체크.
                if (host.startsWith("https://")) {
                    targetPort = 443;
                    isHttps = true;
                }

                // 체크 후에 없애준다. 그래야 inet이 먹음
                host = host.replace("https://", "");
                host = host.replace("http://", "");

                // 포트 정보 있는지 체크. http:를 없앴기 때문에 동작함.
                int portIdx = host.lastIndexOf(":");
                if (portIdx != -1) {
                    int pathIndex = host.indexOf("/");

                    // pathIndex가 있으면, pathIndex까지 뜯고, 없으면 끝까지 뜯는다.
                    String portInfo = host.substring(portIdx + 1, pathIndex == -1 ? host.length() : pathIndex);

                    // 잘못뜯기면 여기서 예외 터짐. 숫자만 들어와야함.
                    targetPort = Integer.parseInt(portInfo);

                    // path 정보가 있는지 확인 후 뜯어준다.
                    if (pathIndex != -1) {
                        path = host.substring(pathIndex);
                        host = host.substring(0, portIdx);
                    } else {
                        host = host.substring(0, portIdx);
                    }
                }
                host = host.replace("/", "");

                InetSocketAddress address = new InetSocketAddress(host, targetPort);
                portMap.put(port, new SocketInfo(address, host, path, isHttps));

            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return portMap;
    }
}
