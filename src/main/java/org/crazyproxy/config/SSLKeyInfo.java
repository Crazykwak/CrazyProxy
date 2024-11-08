package org.crazyproxy.config;

import lombok.Getter;

import javax.net.ssl.KeyManagerFactory;

public class SSLKeyInfo {

    private static SSLKeyInfo instance = null;
    @Getter
    private final KeyManagerFactory keyManagerFactory;

    private SSLKeyInfo(KeyManagerFactory keyManagerFactory) {
        this.keyManagerFactory = keyManagerFactory;
    }

    public static SSLKeyInfo getInstance() {
        if (instance == null) {
            throw new IllegalStateException("SSLKeyInfo has not been initialized yet.");
        }
        return instance;
    }

    public static SSLKeyInfo initInstance(KeyManagerFactory keyManagerFactory) {
        if (instance != null) {
            throw new IllegalStateException("SSLKeyInfo has already been initialized.");
        }
        instance = new SSLKeyInfo(keyManagerFactory);
        return instance;
    }
}
