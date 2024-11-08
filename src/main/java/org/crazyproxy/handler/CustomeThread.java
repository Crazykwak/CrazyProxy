package org.crazyproxy.handler;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.Config;

import java.nio.ByteBuffer;

@Slf4j
@Getter
public class CustomeThread extends Thread {

    private ByteBuffer myAppData = ByteBuffer.allocate(Config.getInstance().getBufferSize());
    private ByteBuffer myNetData = ByteBuffer.allocate(Config.getInstance().getBufferSize());
    private ByteBuffer peerAppData = ByteBuffer.allocate(Config.getInstance().getBufferSize());
    private ByteBuffer peerNetData = ByteBuffer.allocate(Config.getInstance().getBufferSize());
    private ByteBuffer tmpBuffer = ByteBuffer.allocate(Config.getInstance().getBufferSize());

    public CustomeThread(Runnable target) {
        super(target);
    }
}
