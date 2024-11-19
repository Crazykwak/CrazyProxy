package org.crazyproxy.config;

import lombok.Getter;

import java.util.Map;

public class ClientWorkConfig {

    private static ClientWorkConfig instance;

    @Getter
    private final Map<String, SocketInfo> portMap;
    @Getter
    private final int workerCount;
    @Getter
    private final int bufferSize;

    private ClientWorkConfig(Map<String, SocketInfo> portMap, int workerCount, int bufferSize) {
        this.portMap = portMap;
        this.workerCount = workerCount;
        this.bufferSize = bufferSize;
    }

    public static void initInstance(Map<String, SocketInfo> portMap, int workerCount, int bufferSize) {
        if (instance != null) {
            throw new IllegalStateException("Config has already been initialized");
        }
        instance = new ClientWorkConfig(portMap, workerCount, bufferSize);
    }

    public static synchronized ClientWorkConfig getInstance() {
        if (instance == null) {
            throw new IllegalStateException("Config not initialized");
        }
        return instance;
    }

    public String[] getPortMapKeySet() {
        return portMap.keySet().toArray(new String[0]);
    }
}
