package org.crazyproxy.util;

import java.io.IOException;
import java.nio.channels.SocketChannel;

public class SocketUtil {

    private static SocketUtil instance;
    public static SocketUtil getInstance() {
        if (instance == null) {
            instance = new SocketUtil();
        }
        return instance;
    }

    private SocketUtil() {
    }

    public void socketClose(SocketChannel socketChannel) {
        if (socketChannel != null) {
            try {
                socketChannel.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
