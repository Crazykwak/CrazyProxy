package org.crazyproxy.handler;

import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.Config;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

@Slf4j
public class ClientHandler implements NioHandler {

    private final Config config = Config.getInstance();
    private final ExecutorService executor;
    private final ByteBuffer buffer = ByteBuffer.allocate(config.getBufferSize());

    public ClientHandler() {
        ThreadFactory threadFactory = new ThreadFactory() {

            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new CustomeThread(r);
                thread.setDaemon(true);
                return thread;
            }
        };
        executor = Executors.newFixedThreadPool(config.getWorkerCount(), threadFactory);
    }

    @Override
    public void handle(SelectionKey key) throws IOException {
        SocketChannel clientChannel = (SocketChannel) key.channel();

        int readBytes = clientChannel.read(buffer);

        if (readBytes == -1) {
            log.error("readBytes is -1. closing channel");
            clientChannel.close();
            return;
        }

        byte[] inputDataBytes = new byte[readBytes];

        buffer.flip();
        buffer.get(inputDataBytes, 0, readBytes);
        buffer.clear();

        log.info("execute!");
        executor.execute(new ClientWorker(inputDataBytes, key));
    }

}
