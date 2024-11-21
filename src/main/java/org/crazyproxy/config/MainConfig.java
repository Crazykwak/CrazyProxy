package org.crazyproxy.config;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class MainConfig {
    private final String keyFilePath;
    private final String keyPassword;
    private final String keyFactoryPassword;
    private final String trustFilePath;
    private final String trustPassword;
    private final String mappingFilePath;
    private final int workerCount;
    private final int bufferSize;
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
