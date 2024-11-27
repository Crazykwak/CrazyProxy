package org.crazyproxy.handler;

import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.ClientWorkConfig;
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
import java.util.concurrent.Executors;

/**
 * 클라이언트의 요청 서버로 요청 후 클라에게 응답을 주는 클래스
 * ClientHandle에서 스레드풀을 가지고 있었기 때문에, Runnable로 만들어서 썼었음.
 * 수정 필요.
 */
@Slf4j
public class ClientWorker implements Runnable {

    private final ClientWorkConfig clientWorkConfig = ClientWorkConfig.getInstance();
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

    private SocketUtil socketUtil = SocketUtil.getInstance();


    public ClientWorker(byte[] inputDataBytes, SelectionKey clientKey) throws IOException {
        log.debug("init Worker = {}", Thread.currentThread().getName());

        this.inputDataBytes = inputDataBytes;

        SocketChannel clientChannel = (SocketChannel) clientKey.channel();
        InetSocketAddress clientAddress = (InetSocketAddress) clientChannel.getLocalAddress();
        String clientPort = String.valueOf(clientAddress.getPort());
        SocketInfo socketInfo = clientWorkConfig.getPortMap().get(clientPort);
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
                log.debug("[SELECT START]");
                selector.select();

                keys = selector.selectedKeys();
                for (SelectionKey key : keys) {

                    if (key.isConnectable()) {
                        log.debug("\t[CONNECT]");
                        SocketChannel channel = (SocketChannel) key.channel();
                        if (channel.finishConnect()) {
                            log.debug("\t\tConnected!!! host = {}", channel.getRemoteAddress());

                            if (socketInfo.isHttps()) {
                                if (!SSLHandshakeUtil.doHandshake(sslEngine, Executors.newSingleThreadExecutor(), channel, myAppData, myNetData, peerAppData, peerNetData)) {
                                    log.error("\t\thandshake failed. close channel");
                                    socketUtil.socketClose(channel);
                                    socketUtil.socketClose(clientChannel);
                                    continue;
                                }
                            }
                            // 연결이 완료되었으므로 이제 OP_WRITE로 등록합니다.
                            channel.register(selector, SelectionKey.OP_WRITE);
                        }

                    } else if (key.isWritable()) {
                        log.debug("\t[START WRITABLE]");
                        targetChannel = (SocketChannel) key.channel();

                        if (socketInfo.isHttps()) {
                            myNetData.clear();
                            SSLEngineResult result = sslEngine.wrap(myAppData, myNetData);

                            // todo. it's bothering
                            switch (result.getStatus()) {
                                case OK:
                                    log.debug("\t\twrite OK");
                                    myNetData.flip();
                                    while (myNetData.hasRemaining()) {
                                        targetChannel.write(myNetData);
                                    }
                                    break;
                                case BUFFER_OVERFLOW:
                                    log.debug("\t\tBuffer overflow");
                                    myNetData = SSLHandshakeUtil.enlargeApplicationBuffer(myNetData, sslEngine);
                                    break;
                                case BUFFER_UNDERFLOW:
                                    log.debug("\t\tBuffer Underflow");
                                    break;
                                case CLOSED:
                                    log.debug("\t\tConnection closed");
                                    break;
                                default:
                                    throw new IllegalStateException("\t\tUnexpected value: " + result.getStatus());
                            }
                        } else {
                            while (myAppData.hasRemaining()) {
                                targetChannel.write(myAppData);
                            }
                        }

                        key.interestOps(SelectionKey.OP_READ);
                        allBufferClear();

                    } else if (key.isReadable()) {
                        log.debug("\t[START READABLE]");
                        targetChannel = (SocketChannel) key.channel();
                        clientChannel = (SocketChannel) clientKey.channel();

                        if (!targetChannel.isConnected()) {
                            log.warn("\t\ttargetChannel is not connected");
                            continue;
                        }
                        int readBytes = targetChannel.read(peerNetData);

                        if (readBytes > 0) {
                            peerNetData.flip();

                            if (socketInfo.isHttps()) {

                                SSLEngineResult result = null;

                                while (peerNetData.hasRemaining()) {
                                    log.debug("\t\tpeerNetData = {}, {}", peerNetData.limit(), peerNetData.remaining());
                                    result = sslEngine.unwrap(peerNetData, peerAppData);
                                    if (!result.getStatus().equals(SSLEngineResult.Status.OK)) {
                                        break;
                                    }
                                }

                                if (result == null) {
                                    log.error("\t\tresult is null. WHAT THE FUCK");
                                    throw new RuntimeException("result is null");
                                }
                                SSLEngineResult.Status status = result.getStatus();

                                switch (status) {
                                    case OK:
                                        log.debug("\t\tOK");
                                        peerAppData.flip();
                                        clientChannel.write(peerAppData);
                                        allBufferClear();
                                        break;
                                    case BUFFER_UNDERFLOW:
                                        log.debug("\t\tbuffer underflow compact peerNetData");
                                        peerNetData.compact();
                                        break;
                                    case BUFFER_OVERFLOW:
                                        log.debug("\t\tbuffer overflow");
                                        peerAppData = SSLHandshakeUtil.enlargeApplicationBuffer(peerAppData, sslEngine);
                                        break;

                                    case CLOSED:
                                        log.debug("\t\tSSL Engine CLOSED");
                                        socketUtil.socketClose(targetChannel);
                                        socketUtil.socketClose(clientChannel);
                                        allBufferClear();
                                        keepSelect = false;
                                        break;

                                    default:
                                        throw new IllegalStateException("\t\tUnexpected value: " + result.getStatus());
                                }

                            } else {
                                while (peerNetData.hasRemaining()) {
                                    clientChannel.write(peerNetData);
                                }
                                peerNetData.clear();
                            }
                        } else {
                            log.debug("\t\tChannel closed");
                            keepSelect = false;
                            socketUtil.socketClose(targetChannel);
                            socketUtil.socketClose(clientChannel);
                            clientKey.cancel();
                            allBufferClear();
                        }
                    }
                }

                keys.clear();
            }

            selector.close();


        } catch (IOException e) {
            log.error("target write fail!! socket close", e);
            socketUtil.socketClose(clientChannel);
            socketUtil.socketClose(targetChannel);
            throw new RuntimeException(e);
        } finally {
            allBufferClear();
            if (keys != null) {
                keys.clear();
            }
            socketUtil.socketClose(clientChannel);
            socketUtil.socketClose(targetChannel);
        }
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

        String modifyString = stringBuilder.toString();

        return modifyString.getBytes(StandardCharsets.UTF_8);
    }

    private void allBufferClear() {
        myAppData.clear();
        myNetData.clear();
        peerAppData.clear();
        peerNetData.clear();
    }
}
