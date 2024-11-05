package org;

import lombok.extern.slf4j.Slf4j;
import org.config.Config;
import org.config.SSLKeyInfo;
import org.nio.SelectorThread;
import org.config.SocketInfo;

import javax.net.ssl.KeyManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@Slf4j
public class CrazyProxy {

    public static ThreadLocal<ByteBuffer> WriteByteBufferThreadLocal = new ThreadLocal<>();

    public static void main(String[] args) {
//      port : host 맵핑 정보
        log.info("try to portMap setting");
        final Map<String, SocketInfo> portMap = initSocketInfoHashMap();
        log.info("portMap setting done.");

        // todo. need worker count and bufferSize setting
        Config.initInstance(portMap);

        // todo. keyFilePath use -D option
        String keyFilePath = "keystore.p12";
        File keyFile = new File(keyFilePath);
        if (keyFile.exists()) {
            log.info("Key file exists. try to set SSL Key");
            setSSLKeyInfo(keyFilePath);
            log.info("Key set done.");
        }

        SelectorThread selectorThread = new SelectorThread();
        selectorThread.start();

    }

    private static void setSSLKeyInfo(String keyFilePath) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            FileInputStream keyStoreStream = new FileInputStream(keyFilePath);
            keyStore.load(keyStoreStream, "qwerty".toCharArray());
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "qwerty".toCharArray());
            SSLKeyInfo.initInstance(keyManagerFactory);
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
                if (host.startsWith("https://")) {
                    targetPort = 443;
                    isHttps = true;
                }
                host = host.replace("https://", "");
                host = host.replace("http://", "");
                int portIdx = host.lastIndexOf(":");
                if (portIdx != -1) {
                    String portInfo = host.substring(portIdx + 1);
                    if (portInfo.contains("/")) {
                        String[] split = portInfo.split("/", 2);
                        portInfo = split[0];
                        path += split[1];
                    }
                    targetPort = Integer.parseInt(portInfo);
                    host = host.substring(0, portIdx);
                }

                InetSocketAddress address = new InetSocketAddress(host, targetPort);
                portMap.put(port, new SocketInfo(address, path, isHttps));
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        for (String s : portMap.keySet()) {
            System.out.println("s = " + s);
            System.out.println("portMap = " + portMap.get(s));
        }
        return portMap;
    }
}
