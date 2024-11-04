package org;

import jdk.nashorn.internal.parser.JSONParser;
import org.config.Config;
import org.nio.SelectorThread;
import org.nio.SocketInfo;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class CrazyProxy {

    public static ThreadLocal<ByteBuffer> WriteByteBufferThreadLocal = new ThreadLocal<>();

    public static void main(String[] args) {
//      port : host 맵핑 정보
        final Map<String, SocketInfo> portMap = new HashMap<>();

        FileInputStream fis = null;
        try {
            fis = new FileInputStream("mappin.properties");
            Properties properties = new Properties();
            properties.load(fis);

            for (Object key : properties.keySet()) {
                String port = (String) key;
                String host = properties.get(port).toString();
                String path = "/";
                int targetPort = 80;
                if (host.startsWith("https://")) {
                    targetPort = 443;
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
                portMap.put(port, new SocketInfo(address, path));
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

        Config.initInstance(portMap);

        SelectorThread selectorThread = new SelectorThread();
        selectorThread.start();

    }
}
