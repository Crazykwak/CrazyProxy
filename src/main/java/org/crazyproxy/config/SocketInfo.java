package org.crazyproxy.config;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.net.InetSocketAddress;

@AllArgsConstructor
@Getter
public class SocketInfo {

    private InetSocketAddress inetSocketAddress;
    private String path;
    private boolean isHttps;

    @Override
    public String toString() {
        return "SocketInfo [inetSocketAddress=" + inetSocketAddress + ", path=" + path + "]";
    }
}