package org.nio.handler;

import lombok.extern.slf4j.Slf4j;
import org.config.Config;
import org.nio.SocketInfo;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.CrazyProxy.*;

@Slf4j
public class ClientWorker implements Runnable {
    private Config config = Config.getInstance();
    private final byte[] inputDataBytes;
    private final StringBuilder stringBuilder = new StringBuilder();
    private final String clientAddress;
    private final String targetAddress;
    private final SelectionKey clientKey;
    private final Selector selector;
    private final StringBuilder accumulatedData = new StringBuilder();
    private String path = "/";


    public ClientWorker(byte[] inputDataBytes, SelectionKey clientKey) throws IOException {
        log.info("init Worker = {}", Thread.currentThread().getName());
        this.inputDataBytes = inputDataBytes;

        selector = Selector.open();

        SocketChannel clientChannel = (SocketChannel) clientKey.channel();
        InetSocketAddress clientAddress = (InetSocketAddress) clientChannel.getLocalAddress();
        String clientPort = String.valueOf(clientAddress.getPort());
        SocketInfo socketInfo = config.getPortMap().get(clientPort);
        InetSocketAddress inetSocketAddress = socketInfo.getInetSocketAddress();
        this.path = socketInfo.getPath();
        targetAddress = inetSocketAddress.getAddress().getHostAddress();
        SocketChannel targetChannel = SocketChannel.open();
        targetChannel.configureBlocking(false);
        targetChannel.socket().setTcpNoDelay(true);
        targetChannel.connect(inetSocketAddress);

        targetChannel.register(selector, SelectionKey.OP_CONNECT);

        if (targetChannel == null) {
            throw new IOException("Invalid port " + clientPort);
        }

        this.clientAddress = clientAddress.getAddress().getHostAddress();
        this.clientKey = clientKey;
    }

    @Override
    public void run() {
        byte[] modifyBytes = modifyRequestHeader();
        String trim = new String(modifyBytes).trim();
        System.out.println("trim = " + trim);
        ByteBuffer writeBuffer = getByteBuffer();

        writeBuffer.put(modifyBytes);
        writeBuffer.flip();
        log.info("select start!");
        boolean keepSelect = true;
        selector.wakeup();
        try {

            while (keepSelect) {
                int select = selector.select();
                log.info("select = {}", select);

                Set<SelectionKey> keys = selector.selectedKeys();
                for (SelectionKey key : keys) {

                    if (key.isConnectable()) {
                        SocketChannel channel = (SocketChannel) key.channel();
                        if (channel.finishConnect()) {
                            log.info("Connected!!!");
                            // 연결이 완료되었으므로 이제 OP_WRITE로 등록합니다.
                            channel.register(selector, SelectionKey.OP_WRITE);
                        }

                    } else if (key.isWritable()) {
                         SocketChannel targetChannel = (SocketChannel) key.channel();

                        log.info("write");
                        while (writeBuffer.hasRemaining()) {
                            log.info("write buffer write!!");
                            int write = targetChannel.write(writeBuffer);
                            log.info("write byte size = {}", write);
                        }
                        key.interestOps(SelectionKey.OP_READ);
                        writeBuffer.clear();

                    } else if (key.isReadable()) {
                        SocketChannel targetChannel = (SocketChannel) key.channel();

                        log.info("read and ack!");
                        SocketChannel clientChannel = (SocketChannel) clientKey.channel();

                        int readBytes = -1;
                        while ((readBytes = targetChannel.read(writeBuffer)) > 0) {
                            log.info("read byte size = {}", readBytes);
                            writeBuffer.flip();

                            writeBuffer.mark();
                            while (writeBuffer.hasRemaining()) {
                                log.info("write buffer write!!");
                                clientChannel.write(writeBuffer);
                            }
                            writeBuffer.reset();
                            if (isLastChunk(writeBuffer)) {
                                keepSelect = false;
                            }
                            accumulatedData.setLength(0);
                            writeBuffer.clear();
                        }

                        if (readBytes == -1) {
                            keepSelect = false;
                            clientChannel.close();
                            clientKey.cancel();
                        }

                    }
                }

                keys.clear();
            }

            log.info("ack write end!!!!!!!!!!!!!");
            selector.close();


        } catch (IOException e) {
            log.error("target write fail!!", e);
            throw new RuntimeException(e);
        } finally {
            writeBuffer.clear();
        }
    }

    private boolean isLastChunk(ByteBuffer writeBuffer) {

        while (writeBuffer.hasRemaining()) {
            accumulatedData.append((char) writeBuffer.get());
        }

        return accumulatedData.toString().contains("0\r\n\r\n");
    }

    private byte[] modifyRequestHeader() {
        String beforeReq = new String(inputDataBytes).trim();
        String[] lines = beforeReq.split("\r\n");

        stringBuilder.setLength(0);
        boolean hasPath = false;

        for (String line : lines) {
            if (line.startsWith("Host")) {
                stringBuilder.append("Host: ").append(targetAddress).append("\r\n");
                continue;
            }
            if (line.startsWith("Path")) {
                String[] split = line.split(":");
                if (!split[1].trim().equals(path)) {
                    stringBuilder.append("Path").append(this.path).append("\r\n");
                }
                hasPath = true;
                continue;
            }
            stringBuilder.append(line).append("\r\n");
        }
        stringBuilder.append("\r\n");

        if (!hasPath) {
            int i = stringBuilder.indexOf("/");
            stringBuilder.insert(i, this.path);
        }
        return stringBuilder.toString().getBytes(StandardCharsets.UTF_8);
    }

    private ByteBuffer getByteBuffer() {
        ByteBuffer byteBuffer = WriteByteBufferThreadLocal.get();
        if (byteBuffer == null) {
            log.info("byteBuffer is null. new allocate buffer");
            byteBuffer = ByteBuffer.allocate(Config.getInstance().getBufferSize());
            WriteByteBufferThreadLocal.set(byteBuffer);
        }
        return byteBuffer;
    }
}
