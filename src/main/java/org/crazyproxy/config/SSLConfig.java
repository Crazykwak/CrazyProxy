package org.crazyproxy.config;

import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class SSLConfig {

    private static SSLConfig instance;

    private SSLContext context;

    private SSLConfig(SSLContext context) {
        this.context = context;
    }

    public static SSLConfig getInstance() {
        if (instance == null) {
            SSLContext context = null;
            String TLSVersion = System.getProperty("org.crazyproxy.config.SSLConfig.TLS.version", "TLSv1.3");
            log.info("===== SET TLS version: {} =====", TLSVersion);
            try {
                context = SSLContext.getInstance(TLSVersion);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            instance = new SSLConfig(context);
        }

        return instance;
    }

    public SSLContext getContext() {
        return instance.context;
    }
}
