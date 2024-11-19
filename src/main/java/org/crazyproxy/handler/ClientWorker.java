package org.crazyproxy.handler;

import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.Config;
import org.crazyproxy.config.SSLConfig;
import org.crazyproxy.config.SocketInfo;
import org.crazyproxy.util.SSLHandshakeUtil;
import org.crazyproxy.util.SocketUtil;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class ClientWorker implements Runnable {
    private final Config config = Config.getInstance();
    private final byte[] inputDataBytes;
    private final StringBuilder stringBuilder = new StringBuilder();
    private final SocketInfo socketInfo;
    private final String targetAddress;
    private final SelectionKey clientKey;
    private final Selector selector;
    private final StringBuilder accumulatedData = new StringBuilder();
    private SSLEngine sslEngine;
    private String path = "/";
    private ByteBuffer myAppData;
    private ByteBuffer myNetData;
    private ByteBuffer peerAppData;
    private ByteBuffer peerNetData;
    private ByteBuffer tmpBuffer;

    private SocketUtil socketUtil = SocketUtil.getInstance();
    private ExecutorService executor = Executors.newSingleThreadExecutor();


    public ClientWorker(byte[] inputDataBytes, SelectionKey clientKey) throws IOException {
        log.debug("init Worker = {}", Thread.currentThread().getName());

        this.inputDataBytes = inputDataBytes;

        SocketChannel clientChannel = (SocketChannel) clientKey.channel();
        InetSocketAddress clientAddress = (InetSocketAddress) clientChannel.getLocalAddress();
        String clientPort = String.valueOf(clientAddress.getPort());
        SocketInfo socketInfo = config.getPortMap().get(clientPort);
        this.socketInfo = socketInfo;
        InetSocketAddress inetSocketAddress = socketInfo.getInetSocketAddress();
        this.path = socketInfo.getPath();
        targetAddress = socketInfo.getHost();

        SocketChannel targetChannel = SocketChannel.open();
        targetChannel.configureBlocking(false);
        targetChannel.socket().setTcpNoDelay(true);
        targetChannel.connect(inetSocketAddress);

        if (socketInfo.isHttps()) {
                sslEngine = SSLConfig.getInstance().getContext().createSSLEngine();
                sslEngine.setUseClientMode(true);
        }

        selector = Selector.open();
        targetChannel.register(selector, SelectionKey.OP_CONNECT);

        if (targetChannel == null) {
            throw new IOException("Invalid port " + clientPort);
        }

        this.clientKey = clientKey;
    }

    private void setByteBuffer() {
        CustomeThread customeThread = getCustomeThread();
        myAppData = customeThread.getMyAppData();
        myNetData = customeThread.getMyNetData();
        peerAppData = customeThread.getPeerAppData();
        peerNetData = customeThread.getPeerNetData();
        tmpBuffer = customeThread.getTmpBuffer();

        myNetData.clear();
        peerNetData.clear();
        peerAppData.clear();
        peerNetData.clear();
    }

    private static CustomeThread getCustomeThread() {
        Thread thread = Thread.currentThread();
        if (!(thread instanceof CustomeThread)) {
            throw new RuntimeException("Unexpected thread " + thread.getClass().getName());
        }
        CustomeThread customeThread = (CustomeThread) thread;
        return customeThread;
    }

    @Override
    public void run() {
        setByteBuffer();
        Set<SelectionKey> keys = null;
        byte[] modifyBytes = modifyRequestHeader();

        SocketChannel clientChannel = null;
        SocketChannel targetChannel = null;

        myAppData.clear();
        myAppData.put(modifyBytes);
        myAppData.flip();
        boolean keepSelect = true;
        selector.wakeup();
        try {

            while (keepSelect) {
                selector.select();

                keys = selector.selectedKeys();
                for (SelectionKey key : keys) {

                    if (key.isConnectable()) {
                        SocketChannel channel = (SocketChannel) key.channel();
                        if (channel.finishConnect()) {
                            log.debug("Connected!!! host = {}", channel.getRemoteAddress());

                            if (socketInfo.isHttps()) {
                                if (!SSLHandshakeUtil.doHandshake(sslEngine, executor, channel, myAppData, myNetData, peerAppData, peerNetData)) {
                                    log.error("handshake failed. close channel");
                                    socketUtil.socketClose(channel);
                                    socketUtil.socketClose(clientChannel);
                                    continue;
                                }
                            }
                            // 연결이 완료되었으므로 이제 OP_WRITE로 등록합니다.
                            channel.register(selector, SelectionKey.OP_WRITE);
                        }

                    } else if (key.isWritable()) {
                        targetChannel = (SocketChannel) key.channel();
                        ByteBuffer realWriteBuffer = myAppData;

                        if (socketInfo.isHttps()) {
                            SSLEngineResult result = sslEngine.wrap(myAppData, tmpBuffer);

                            // todo. it's bothering
                            switch (result.getStatus()) {
                                case OK:
                                    log.debug("write OK");
                                    tmpBuffer.flip();
                                    realWriteBuffer = tmpBuffer;
                                    break;
                                case BUFFER_OVERFLOW:
                                    log.debug("Buffer overflow");
                                    break;
                                case BUFFER_UNDERFLOW:
                                    log.debug("Buffer Underflow");
                                    break;
                                case CLOSED:
                                    log.debug("Connection closed");
                                    break;
                                default:
                                    throw new IllegalStateException("Unexpected value: " + result.getStatus());
                            }
                        }

                        while (realWriteBuffer.hasRemaining()) {
                            targetChannel.write(realWriteBuffer);
                        }

                        key.interestOps(SelectionKey.OP_READ);
                        realWriteBuffer.clear();
                        myAppData.clear();

                    } else if (key.isReadable()) {
                        targetChannel = (SocketChannel) key.channel();
                        clientChannel = (SocketChannel) clientKey.channel();
                        myAppData.clear();

                        int readBytes = targetChannel.read(myAppData);
                        if (readBytes > 0) {
                            myAppData.flip();
                            ByteBuffer realReadBuffer = myAppData;

                            if (socketInfo.isHttps()) {
                                tmpBuffer.clear();

                                SSLEngineResult result = null;
                                result = sslEngine.unwrap(realReadBuffer, tmpBuffer);

                                while (realReadBuffer.hasRemaining()) {
                                    result = sslEngine.unwrap(realReadBuffer, tmpBuffer);
                                }
                                SSLEngineResult.Status status = result.getStatus();

                                switch (status) {
                                    case OK:
                                        log.debug("OK");
                                        tmpBuffer.flip();
                                        realReadBuffer = tmpBuffer;
                                        break;
                                    case BUFFER_UNDERFLOW:
                                        log.debug("buffer underflow");
                                        break;
                                    case BUFFER_OVERFLOW:
                                        log.debug("buffer overflow");
                                        tmpBuffer = SSLHandshakeUtil.enlargeApplicationBuffer(tmpBuffer, sslEngine);
                                        break;
                                    case CLOSED:
                                        log.debug("SSL Engine CLOSED");
                                        break;
                                    default:
                                        throw new IllegalStateException("Unexpected value: " + result.getStatus());
                                }
                            }

                            realReadBuffer.mark();
                            while (realReadBuffer.hasRemaining()) {
                                log.debug("write buffer write!!");
                                clientChannel.write(realReadBuffer);
                            }
                            realReadBuffer.reset();
                            if (isLastChunk(realReadBuffer)) {
                                keepSelect = false;
                            }
                            accumulatedData.setLength(0);
                            realReadBuffer.clear();
                            myAppData.clear();
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

            log.debug("ack write end!!!!!!!!!!!!!");
            selector.close();


        } catch (IOException e) {
            log.error("target write fail!! socket close", e);
            socketUtil.socketClose(clientChannel);
            socketUtil.socketClose(targetChannel);
            throw new RuntimeException(e);
        } finally {
            myAppData.clear();
            if (keys != null) {
                keys.clear();
            }
        }
    }

    /**
     * 청크방식의 통신시 마지막 청크인지 확인하는 메서드
     * 문제는 html 내부에 그냥 0\r\n\r\n 이 있을 경우를 못거른다.
     * 이 메서드를 없애야함.
     * @param writeBuffer
     * @return booelan
     */
    private boolean isLastChunk(ByteBuffer writeBuffer) {

        while (writeBuffer.hasRemaining()) {
            accumulatedData.append((char) writeBuffer.get());
        }
        return accumulatedData.toString().contains("0\r\n\r\n");
    }

    /**
     * 클라이언트가 보낸 요청을 변조한다.
     * Host가 프록시 서버 주소로 돼 있으므로, 진짜 요청 주소로 변경
     * 겸사겸사 Path도 변경해준다.
     * @return 변경된 byte[]
     */
    private byte[] modifyRequestHeader() {
        String beforeReq = new String(inputDataBytes).trim();
        String[] lines = beforeReq.split("\r\n");

        stringBuilder.setLength(0);

        for (String line : lines) {
            if (line.startsWith("Host")) {
                stringBuilder.append("Host: ").append(targetAddress).append("\r\n");
                continue;
            }
            stringBuilder.append(line).append("\r\n");
        }
        stringBuilder.append("\r\n");

        // 첫줄의 path를 변경해준다. 디폴트는 "/"
        int pathIndex = stringBuilder.indexOf("/");
        if (pathIndex != -1) {
            stringBuilder.deleteCharAt(pathIndex);
            stringBuilder.insert(pathIndex, this.path);
        }

        log.info("str = {}", stringBuilder.toString());

        return stringBuilder.toString().getBytes(StandardCharsets.UTF_8);
    }
}
