package org.crazyproxy.exception;

public class MainConfigNotFoundException extends RuntimeException {


    public MainConfigNotFoundException(String mainConfigIsNull) {
        super(mainConfigIsNull);
    }
}
