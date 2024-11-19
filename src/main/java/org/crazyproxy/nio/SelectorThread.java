package org.crazyproxy.nio;

import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.ClientWorkConfig;
import org.crazyproxy.config.SocketInfo;
import org.crazyproxy.handler.AcceptHandler;
import org.crazyproxy.handler.NioHandler;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.util.Map;
import java.util.Set;

@Slf4j
public class SelectorThread extends Thread {

    boolean bStop = false;
    private Selector selector;
    private final ClientWorkConfig clientWorkConfig = ClientWorkConfig.getInstance();

    public void run() {

        try {
            selector = Selector.open();

            // 지정된 포트로 서버 열기
            openPorts();

        } catch (IOException e) {
            log.error("port accept IOException. please check portMap configuration",e);
            throw new RuntimeException(e);
        }

        while (!bStop) {

            Set<SelectionKey> selectionKeys = null;

            try {
                selector.select();

                selectionKeys = selector.selectedKeys();

                NioHandler socketHandler = null;

                for (SelectionKey selectionKey : selectionKeys) {
                    // attach를 통해 handler를 만드므로 지정된 이벤트를 제외하고 모두 attachment() 로 처리 가능
                    if (selectionKey.isAcceptable() || selectionKey.isReadable()) {
                        socketHandler = (NioHandler) selectionKey.attachment();
                    }

                    if (socketHandler == null) {
                        throw new RuntimeException("socket handler is null");
                    }

                    socketHandler.handle(selectionKey);
                }

                selectionKeys.clear();

            } catch (IOException e) {
                if (selectionKeys != null) {
                    selectionKeys.clear();
                }
                log.error("error!");
                throw new RuntimeException(e);
            }

        }

    }

    private void openPorts() throws IOException {
        log.info("Listening port setting start");
        Map<String, SocketInfo> portMap = clientWorkConfig.getPortMap();
        for (String port : clientWorkConfig.getPortMapKeySet()) {
            ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.socket().bind(new InetSocketAddress(Integer.parseInt(port)));
            serverSocketChannel.configureBlocking(false);
            SelectionKey register = serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);
            register.attach(new AcceptHandler());
            SocketInfo socketInfo = portMap.get(port);
            log.info("Listening on port = {}, target = {}, path = {}", port, socketInfo.getInetSocketAddress().toString(), socketInfo.getPath());

        }
        log.info("Listening on all ports and targets");
    }
}
