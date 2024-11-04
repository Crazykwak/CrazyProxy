package org.nio.handler;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

@Slf4j
public class AcceptHandler implements NioHandler {

    @Override
    public void handle(SelectionKey key) throws IOException {
        ServerSocketChannel socketChannel = (ServerSocketChannel) key.channel();

        SocketChannel acceptChannel = socketChannel.accept();
        acceptChannel.configureBlocking(false);
        SelectionKey clientKey = acceptChannel.register(key.selector(), SelectionKey.OP_READ);
        clientKey.attach(new ClientHandler());
        InetSocketAddress remoteSocketAddress = (InetSocketAddress) acceptChannel.socket().getRemoteSocketAddress();
        log.info("Accepted connection from {}", remoteSocketAddress.getAddress().getHostAddress());

    }
}
