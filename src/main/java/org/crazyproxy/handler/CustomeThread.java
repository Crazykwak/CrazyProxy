package org.crazyproxy.handler;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.ClientWorkConfig;

import java.nio.ByteBuffer;

@Slf4j
@Getter
public class CustomeThread extends Thread {

    private ByteBuffer myAppData = ByteBuffer.allocate(ClientWorkConfig.getInstance().getBufferSize());
    private ByteBuffer myNetData = ByteBuffer.allocate(ClientWorkConfig.getInstance().getBufferSize());
    private ByteBuffer peerAppData = ByteBuffer.allocate(ClientWorkConfig.getInstance().getBufferSize());
    private ByteBuffer peerNetData = ByteBuffer.allocate(ClientWorkConfig.getInstance().getBufferSize());
    private ByteBuffer tmpBuffer = ByteBuffer.allocate(ClientWorkConfig.getInstance().getBufferSize());

    public CustomeThread(Runnable target) {
        super(target);
    }
}
