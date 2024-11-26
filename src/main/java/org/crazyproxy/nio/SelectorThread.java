package org.crazyproxy.nio;

import lombok.extern.slf4j.Slf4j;
import org.crazyproxy.config.ClientWorkConfig;
import org.crazyproxy.config.SocketInfo;
import org.crazyproxy.handler.AcceptHandler;
import org.crazyproxy.handler.CustomeThread;
import org.crazyproxy.handler.NioHandler;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

@Slf4j
public class SelectorThread extends Thread {

    boolean bStop = false;
    private Selector selector;
    private final ExecutorService executor;
    private final ClientWorkConfig clientWorkConfig = ClientWorkConfig.getInstance();

    public SelectorThread() {
        ThreadFactory threadFactory = new ThreadFactory() {

            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new CustomeThread(r);
                thread.setDaemon(true);
                return thread;
            }
        };
        executor = Executors.newFixedThreadPool(clientWorkConfig.getWorkerCount(), threadFactory);
    }

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


                for (SelectionKey selectionKey : selectionKeys) {

                    if (selectionKey.isValid() && selectionKey.isAcceptable()) {
                        NioHandler socketHandler = (NioHandler) selectionKey.attachment();
                        socketHandler.handle(selectionKey);
                    } else if (selectionKey.isValid() && selectionKey.isReadable()) {
                        NioHandler socketHandler = (NioHandler) selectionKey.attachment();

                        executor.execute(() -> {
                            try {
                                if (selectionKey.channel().isOpen()){
                                    socketHandler.handle(selectionKey);
                                }
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        });
                    }
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
