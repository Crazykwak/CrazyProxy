package org.crazyproxy.config;

import lombok.Getter;

import java.util.Map;

public class Config {

    private static Config instance;
    @Getter
    private final Map<String, SocketInfo> portMap;
    @Getter
    private final int workerCount;
    @Getter
    private final int bufferSize;

    private Config(Map<String, SocketInfo> portMap, int workerCount, int bufferSize) {
        this.portMap = portMap;
        this.workerCount = workerCount;
        this.bufferSize = bufferSize;
    }

    // 인스턴스를 얻는 메서드
    public static void initInstance(Map<String, SocketInfo> portMap) {
        if (instance != null) {
            throw new IllegalStateException("Config has already been initialized");
        }
        initInstance(portMap, 50);
    }
    public static void initInstance(Map<String, SocketInfo> portMap, int workerCount) {
        if (instance != null) {
            throw new IllegalStateException("Config has already been initialized");
        }
        initInstance(portMap, workerCount, 1024 * 100);
    }

    public static void initInstance(Map<String, SocketInfo> portMap, int workerCount, int bufferSize) {
        if (instance != null) {
            throw new IllegalStateException("Config has already been initialized");
        }
        instance = new Config(portMap, workerCount, bufferSize);
    }

    public static synchronized Config getInstance() {
        if (instance == null) {
            throw new IllegalStateException("Config not initialized");
        }
        return instance;
    }

    public String[] getPortMapKeySet() {
        return portMap.keySet().toArray(new String[0]);
    }
}
