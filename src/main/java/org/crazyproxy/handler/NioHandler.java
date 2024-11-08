package org.crazyproxy.handler;

import java.io.IOException;
import java.nio.channels.SelectionKey;

public interface NioHandler {
    void handle(SelectionKey key) throws IOException;
}
