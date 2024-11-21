package org.crazyproxy.config;

import lombok.Builder;

@Builder
public record MainConfig(String keyFilePath, String keyPassword, String keyFactoryPassword, String trustFilePath,
                         String trustPassword, String mappingFilePath, int workerCount, int bufferSize) {
    @Override
    public String toString() {
        return "MainConfig{\n" +
                "keyFIlePath='" + keyFilePath + '\'' + '\n' +
                ", keyPassword='" + keyPassword + '\'' + '\n' +
                ", keyFactoryPassword='" + keyFactoryPassword + '\'' + '\n' +
                ", trustFilePath='" + trustFilePath + '\'' + '\n' +
                ", trustPassword='" + trustPassword + '\'' + '\n' +
                ", mappingFilePath='" + mappingFilePath + '\'' + '\n' +
                ", workerCount=" + workerCount + '\n' +
                ", bufferSize=" + bufferSize +
                '}';
    }
}
