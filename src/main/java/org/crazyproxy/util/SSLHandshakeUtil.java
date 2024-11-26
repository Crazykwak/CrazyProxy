package org.crazyproxy.util;

import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ExecutorService;

@Slf4j
public class SSLHandshakeUtil {


    /**
     * SSL 헨드세이크 메서드. SSL 상태는 SSLEngine마다 다르기 때문에, 모든 연결에서 이 메서드를 호출해야 함.
     * @param sslEngine SSLContext로 뽑은 SSLEngine
     * @param executor needTask 상태시 만들 Executor service
     * @param channel target Channel. 핸드세이크할 서버
     * @param myAppData 클라이언트 데이터
     * @param myNetData wrap 된 클라이언트 데이터
     * @param peerAppData 서버 데이터
     * @param peerNetData unwrap 한 서버 데이터
     * @return
     * @throws IOException
     */
    public static boolean doHandshake(SSLEngine sslEngine,
                                      ExecutorService executor,
                                      SocketChannel channel,
                                      ByteBuffer myAppData,
                                      ByteBuffer myNetData,
                                      ByteBuffer peerAppData,
                                      ByteBuffer peerNetData) throws IOException {
        sslEngine.beginHandshake();
        SSLEngineResult.HandshakeStatus handshakeStatus = sslEngine.getHandshakeStatus();

        while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED &&
                handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

            switch (handshakeStatus) {
                case NEED_WRAP:
                    handshakeStatus = handleWrap(sslEngine, channel, myAppData, myNetData);
                    break;

                case NEED_UNWRAP:
                    handshakeStatus = handleUnwrap(sslEngine, channel, peerAppData, peerNetData);
                    if (handshakeStatus == null) return false;
                    break;

                case NEED_TASK:
                    handshakeStatus = runDelegatedTasks(sslEngine, executor);
                    break;

                case FINISHED:
                case NOT_HANDSHAKING:
                    break;

                default:
                    throw new IllegalStateException("Invalid SSL status: " + handshakeStatus);
            }
        }

        log.debug("Handshake completed with status: {}", handshakeStatus);
        return true;
    }

    private static SSLEngineResult.HandshakeStatus handleWrap(SSLEngine sslEngine,
                                                              SocketChannel channel,
                                                              ByteBuffer myAppData,
                                                              ByteBuffer myNetData) throws IOException {
        myNetData.clear();
        SSLEngineResult result;

        try {
            result = sslEngine.wrap(myAppData, myNetData);
        } catch (SSLException e) {
            log.error("SSL wrap failed", e);
            sslEngine.closeOutbound();
            return sslEngine.getHandshakeStatus();
        }

        switch (result.getStatus()) {
            case OK:
                myNetData.flip();
                while (myNetData.hasRemaining()) {
                    channel.write(myNetData);
                }
                break;

            case BUFFER_OVERFLOW:
                myNetData = enlargeBuffer(myNetData, sslEngine.getSession().getPacketBufferSize());
                break;

            case BUFFER_UNDERFLOW:
                throw new SSLException("Buffer underflow during wrap");

            case CLOSED:
                closeConnection(channel, myNetData);
                break;
        }

        return result.getHandshakeStatus();
    }

    private static SSLEngineResult.HandshakeStatus handleUnwrap(SSLEngine sslEngine,
                                                                SocketChannel channel,
                                                                ByteBuffer peerAppData,
                                                                ByteBuffer peerNetData) throws IOException {
        if (channel.read(peerNetData) < 0) {
            if (sslEngine.isInboundDone() && sslEngine.isOutboundDone()) {
                return null;
            }
            handleEndOfStream(sslEngine);
            return sslEngine.getHandshakeStatus();
        }

        peerNetData.flip();
        SSLEngineResult result;

        try {
            result = sslEngine.unwrap(peerNetData, peerAppData);
            peerNetData.compact();
        } catch (SSLException e) {
            log.error("SSL unwrap failed", e);
            sslEngine.closeOutbound();
            return sslEngine.getHandshakeStatus();
        }

        switch (result.getStatus()) {
            case OK:
                break;

            case BUFFER_OVERFLOW:
                peerAppData = enlargeBuffer(peerAppData, sslEngine.getSession().getApplicationBufferSize());
                break;

            case BUFFER_UNDERFLOW:
                peerNetData = handleBufferUnderflow(sslEngine, peerNetData);
                break;

            case CLOSED:
                closeOutbound(sslEngine);
                break;
        }

        return result.getHandshakeStatus();
    }

    private static SSLEngineResult.HandshakeStatus runDelegatedTasks(SSLEngine sslEngine, ExecutorService executor) {
        Runnable task;
        while ((task = sslEngine.getDelegatedTask()) != null) {
            executor.execute(task);
        }
        return sslEngine.getHandshakeStatus();
    }

    private static ByteBuffer handleBufferUnderflow(SSLEngine sslEngine, ByteBuffer buffer) {
        if (sslEngine.getSession().getPacketBufferSize() < buffer.limit()) {
            return buffer;
        }
        ByteBuffer newBuffer = enlargeBuffer(buffer, sslEngine.getSession().getPacketBufferSize());
        buffer.flip();
        newBuffer.put(buffer);
        return newBuffer;
    }

    private static ByteBuffer enlargeBuffer(ByteBuffer buffer, int sessionSize) {
        if (sessionSize > buffer.capacity()) {
            log.debug("\tBufferOverflow session size > buffer.capacity");
            return ByteBuffer.allocate(sessionSize);
        } else {
            log.debug("\tBufferOverflow session size < buffer.capacity");
            return ByteBuffer.allocate(buffer.capacity() * 2);
        }
    }

    private static void handleEndOfStream(SSLEngine sslEngine) throws SSLException {
        try {
            sslEngine.closeInbound();
        } catch (SSLException e) {
            log.error("Error closing SSL inbound", e);
        }
        sslEngine.closeOutbound();
    }

    private static void closeOutbound(SSLEngine sslEngine) throws IOException {
        if (!sslEngine.isOutboundDone()) {
            sslEngine.closeOutbound();
        }
    }

    private static void closeConnection(SocketChannel channel, ByteBuffer myNetData) throws IOException {
        myNetData.flip();
        while (myNetData.hasRemaining()) {
            channel.write(myNetData);
        }
    }

    public static ByteBuffer enlargeApplicationBuffer(ByteBuffer tmpBuffer, SSLEngine sslEngine) {
        return enlargeBuffer(tmpBuffer, sslEngine.getSession().getApplicationBufferSize());
    }
}
