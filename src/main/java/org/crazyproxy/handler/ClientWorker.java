package org.crazyproxy.handler;

import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.Config;
import org.crazyproxy.config.SSLConfig;
import org.crazyproxy.config.SocketInfo;

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
    private Config config = Config.getInstance();
    private final byte[] inputDataBytes;
    private final StringBuilder stringBuilder = new StringBuilder();
    private final String clientAddress;
    private final SocketInfo socketInfo;
    private final String targetAddress;
    private final SelectionKey clientKey;
    private final Selector selector;
    private final StringBuilder accumulatedData = new StringBuilder();
    private SSLContext sslContext;
    private SSLEngine sslEngine;
    private String path = "/";
    private ByteBuffer myAppData;
    private ByteBuffer myNetData;
    private ByteBuffer peerAppData;
    private ByteBuffer peerNetData;
    private ByteBuffer tmpBuffer;

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
        targetAddress = inetSocketAddress.getAddress().getHostAddress();

        SocketChannel targetChannel = SocketChannel.open();
        targetChannel.configureBlocking(false);
        targetChannel.socket().setTcpNoDelay(true);
        targetChannel.connect(inetSocketAddress);

        if (socketInfo.isHttps()) {
                sslContext = SSLConfig.getInstance().getContext();
                sslEngine = sslContext.createSSLEngine();
                sslEngine.setUseClientMode(true);
        }

        selector = Selector.open();
        targetChannel.register(selector, SelectionKey.OP_CONNECT);

        if (targetChannel == null) {
            throw new IOException("Invalid port " + clientPort);
        }

        this.clientAddress = clientAddress.getAddress().getHostAddress();
        this.clientKey = clientKey;

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

    private boolean doHandShake(SocketChannel targetChannel) throws IOException, InterruptedException {
        sslEngine.beginHandshake();
        SSLEngineResult.HandshakeStatus handshakeStatus = sslEngine.getHandshakeStatus();
        SSLEngineResult result;

        while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED &&
                handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

            switch (handshakeStatus) {
                case NEED_WRAP:
                    myNetData.clear();
                    try {
                        result = sslEngine.wrap(myAppData, myNetData);
                        handshakeStatus = result.getHandshakeStatus();
                    } catch (SSLException e) {
                        log.error("A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...", e);
                        sslEngine.closeOutbound();
                        handshakeStatus = sslEngine.getHandshakeStatus();
                        break;
                    }

                    switch (result.getStatus()) {
                        case OK:
                            myNetData.flip();
                            while (myNetData.hasRemaining()) {
                                targetChannel.write(myNetData);
                            }
                            break;
                        case BUFFER_UNDERFLOW:
                            throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
                        case BUFFER_OVERFLOW:
                            myNetData = enlargePacketBuffer(myNetData);
                            break;
                        case CLOSED:
                            try {
                                myNetData.flip();
                                while (myNetData.hasRemaining()) {
                                    targetChannel.write(myNetData);
                                }
                                // At this point the handshake status will probably be NEED_UNWRAP so we make sure that peerNetData is clear to read.
                                peerNetData.clear();
                            } catch (Exception e) {
                                log.error("Failed to send server's CLOSE message due to socket channel's failure.");
                                handshakeStatus = sslEngine.getHandshakeStatus();
                            }
                            break;
                        default:
                            throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                    }
                    break;

                case NEED_UNWRAP:
                    if (targetChannel.read(peerNetData) < 0) {
                        if (sslEngine.isInboundDone() && sslEngine.isOutboundDone()) {
                            return false;
                        }
                        try {
                            sslEngine.closeInbound();
                        } catch (SSLException e) {
                            log.error("This engine was forced to close inbound, without having received the proper SSL/TLS close notification message from the peer, due to end of stream.");
                        }
                        sslEngine.closeOutbound();
                        handshakeStatus = sslEngine.getHandshakeStatus();
                        break;
                    }
                    peerNetData.flip();
                    try {
                        result = sslEngine.unwrap(peerNetData, peerAppData);
                        peerNetData.compact();
                        handshakeStatus = result.getHandshakeStatus();
                    } catch (SSLException e) {
                        log.error("A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection... {}", e.getMessage());
                        sslEngine.closeOutbound();
                        handshakeStatus = sslEngine.getHandshakeStatus();
                        return false;
                    }
                    switch (result.getStatus()) {
                        case OK:
                            break;
                        case BUFFER_UNDERFLOW:
                            peerNetData = handleBufferUnderFlow(peerNetData);
                            break;
                        case BUFFER_OVERFLOW:
                            peerAppData = enlargeApplicationBuffer(peerAppData);
                            break;
                        case CLOSED:
                            if (sslEngine.isOutboundDone()) {
                                return false;
                            }
                            sslEngine.closeOutbound();
                            handshakeStatus = sslEngine.getHandshakeStatus();
                            break;
                        default:
                            throw new IllegalStateException("Unexpected value: " + result.getStatus());
                    }
                    break;

                case NEED_TASK:
                    Runnable task;
                    while ((task = sslEngine.getDelegatedTask()) != null) {
                        executor.execute(task);
                    }
                    handshakeStatus = sslEngine.getHandshakeStatus();
                    break;

                case FINISHED:
                    log.info("handshake finished");
                    break;
                case NOT_HANDSHAKING:
                    log.info("handshake not_handshaking");
                    break;
                default:
                    throw new IllegalStateException("Invalid Handshake Status: " + handshakeStatus);
            }
        }

        return true;

    }

    private ByteBuffer handleBufferUnderFlow(ByteBuffer buffer) {
        if (sslEngine.getSession().getPacketBufferSize() < buffer.limit()) {
            return buffer;
        }
        ByteBuffer replaceBuffer = enlargePacketBuffer(buffer);
        buffer.flip();
        replaceBuffer.put(buffer);
        return replaceBuffer;
    }

    private ByteBuffer enlargePacketBuffer(ByteBuffer buffer) {
        return enlargeBuffer(buffer, sslEngine.getSession().getPacketBufferSize());
    }

    private ByteBuffer enlargeApplicationBuffer(ByteBuffer buffer) {
        return enlargeBuffer(buffer, sslEngine.getSession().getApplicationBufferSize());
    }

    private ByteBuffer enlargeBuffer(ByteBuffer buffer, int applicationBufferSize) {
        if (applicationBufferSize > buffer.capacity()) {
            buffer = ByteBuffer.allocate(applicationBufferSize);
        } else {
            buffer = ByteBuffer.allocate(buffer.capacity() * 2);
        }
        return buffer;
    }

    @Override
    public void run() {
        Set<SelectionKey> keys = null;
        byte[] modifyBytes = modifyRequestHeader();

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
                            log.info("Connected!!! host = {}", channel.getRemoteAddress());

                            if (socketInfo.isHttps()) {
                                if (!doHandShake(channel)) {
                                    log.error("handshake failed. close channel");
                                    channel.close();
                                    clientKey.channel().close();
                                    continue;
                                }
                            }
                            // 연결이 완료되었으므로 이제 OP_WRITE로 등록합니다.
                            channel.register(selector, SelectionKey.OP_WRITE);
                        }

                    } else if (key.isWritable()) {
                        SocketChannel targetChannel = (SocketChannel) key.channel();
                        ByteBuffer realWriteBuffer = myAppData;

                        if (socketInfo.isHttps()) {
                            //todo 버퍼 알록 고쳐야함.
                            SSLSession session = sslEngine.getSession();
                            ByteBuffer tmpBuffer = ByteBuffer.allocate(session.getPacketBufferSize());
                            SSLEngineResult result = sslEngine.wrap(myAppData, tmpBuffer);

                            switch (result.getStatus()) {
                                case OK:
                                    log.info("write OK");
                                    tmpBuffer.flip();
                                    realWriteBuffer = tmpBuffer;
                                    break;
                                case BUFFER_OVERFLOW:
                                    log.info("Buffer overflow");
                                    break;
                                case BUFFER_UNDERFLOW:
                                    log.info("Buffer Underflow");
                                    break;
                                case CLOSED:
                                    log.info("Connection closed");
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
                        SocketChannel targetChannel = (SocketChannel) key.channel();
                        SocketChannel clientChannel = (SocketChannel) clientKey.channel();
                        myAppData.clear();

                        int readBytes = targetChannel.read(myAppData);
                        if (readBytes > 0) {
                            myAppData.flip();
                            ByteBuffer realReadBuffer = myAppData;

                            if (socketInfo.isHttps()) {
                                ByteBuffer tmpBuffer = ByteBuffer.allocate(sslEngine.getSession().getApplicationBufferSize());
                                tmpBuffer.clear();

                                SSLEngineResult result = null;
                                result = sslEngine.unwrap(realReadBuffer, tmpBuffer);

                                while (realReadBuffer.hasRemaining()) {
                                    result = sslEngine.unwrap(realReadBuffer, tmpBuffer);
                                }
                                SSLEngineResult.Status status = result.getStatus();

                                log.info("status = {}", status);
                                switch (status) {
                                    case OK:
                                        tmpBuffer.flip();
                                        log.info("tmpBuffer remaining = {}", tmpBuffer);
                                        log.info("realReadBuffer remaining = {}", realReadBuffer);
                                        log.debug("str = {}, realbuff = {}",
                                                new String(tmpBuffer.array(), tmpBuffer.position(), tmpBuffer.limit()),
                                                new String(realReadBuffer.array(), 0, realReadBuffer.position()));
                                        realReadBuffer = tmpBuffer;
                                        break;
                                    case BUFFER_UNDERFLOW:
                                        log.info("buffer underflow");
                                        break;
                                    case BUFFER_OVERFLOW:
                                        log.info("buffer overflow");
                                        tmpBuffer = enlargeApplicationBuffer(tmpBuffer);
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
            log.error("target write fail!!", e);
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
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
        int i = stringBuilder.indexOf("/");
        stringBuilder.deleteCharAt(i);
        stringBuilder.insert(i, this.path);

        return stringBuilder.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static CustomeThread getCustomeThread() {
        Thread thread = Thread.currentThread();
        if (!(thread instanceof CustomeThread)) {
            throw new RuntimeException("Unexpected thread " + thread.getClass().getName());
        }
        CustomeThread customeThread = (CustomeThread) thread;
        return customeThread;
    }
}
