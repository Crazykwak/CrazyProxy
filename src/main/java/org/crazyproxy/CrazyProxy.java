package org.crazyproxy;

import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.Config;
import org.crazyproxy.config.SSLConfig;
import org.crazyproxy.config.SSLKeyInfo;
import org.crazyproxy.nio.SelectorThread;
import org.crazyproxy.config.SocketInfo;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@Slf4j
public class CrazyProxy {

    public static void main(String[] args) {
//      port : host 맵핑 정보
        log.info("try to portMap setting");
        final Map<String, SocketInfo> portMap = initSocketInfoHashMap();
        log.info("portMap setting done.");

        // todo. need worker count and bufferSize setting
        Config.initInstance(portMap);

        // todo. keyFilePath use -D option
        String keyFilePath = System.getProperty("org.crazyproxy.keyFilePath", "server.jks");
        File keyFile = new File(keyFilePath);
        SSLKeyInfo sslKeyInfo = null;
        if (keyFile.exists()) {
            log.info("Key file exists. try to set SSL Key");
            sslKeyInfo = setSSLKeyInfo(keyFilePath);
            log.info("Key set done.");

            String trustedCert = System.getProperty("org.crazyproxy.trustedCert", "trustedCerts.jsk");
            File trustedCertFile = new File(trustedCert);
            TrustManager[] trustManagers = null;
            SSLConfig sslConfig = SSLConfig.getInstance();
            SSLContext sslContext = sslConfig.getContext();

            try {
                trustManagers = createTrustManager(trustedCertFile, "storepass");
                sslContext.init(sslKeyInfo.getKeyManagerFactory().getKeyManagers(), trustManagers, new SecureRandom());
            } catch (KeyManagementException e) {
                throw new RuntimeException(e);
            }
        }

        SelectorThread selectorThread = new SelectorThread();
        selectorThread.start();

    }

    private static SSLKeyInfo setSSLKeyInfo(String keyFilePath) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            FileInputStream keyStoreStream = new FileInputStream(keyFilePath);
            keyStore.load(keyStoreStream, "storepass".toCharArray());
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "keypass".toCharArray());
            SSLKeyInfo.initInstance(keyManagerFactory);
            return SSLKeyInfo.getInstance();
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            log.error("Key file not found. keyFilePath = {}", keyFilePath);
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static TrustManager[] createTrustManager(File trustedCertFile, String keystorePassword) {
        InputStream trustStoreIS = null;
        KeyStore trustStore = null;
        if (trustedCertFile.exists()) {
            try {
                trustStore = KeyStore.getInstance("JKS");
                trustStoreIS = new FileInputStream(trustedCertFile.getAbsolutePath());
                trustStore.load(trustStoreIS, keystorePassword.toCharArray());
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (KeyStoreException e) {
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

        TrustManagerFactory trustFactory = null;
        try {
            trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            trustFactory.init((KeyStore) trustStore);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        return trustFactory.getTrustManagers();

    }

    private static Map<String, SocketInfo> initSocketInfoHashMap() {
        final Map<String, SocketInfo> portMap = new HashMap<>();

        FileInputStream fis = null;
        try {
            fis = new FileInputStream("mapping.properties");
            Properties properties = new Properties();
            properties.load(fis);

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
                    String portInfo = host.substring(portIdx + 1);
                    targetPort = Integer.parseInt(portInfo);
                    host = host.substring(0, portIdx);
                }

                // path 정보 추출
                int pathIndex = host.indexOf("/");
                if (pathIndex != -1) {
                    path = host.substring(pathIndex);
                    host = host.substring(0, pathIndex);
                }

                // Innet객체 생성하여 socketInfo를 만들어주자.
                InetSocketAddress address = new InetSocketAddress(host, targetPort);
                portMap.put(port, new SocketInfo(address, path, isHttps));

            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return portMap;
    }
}
