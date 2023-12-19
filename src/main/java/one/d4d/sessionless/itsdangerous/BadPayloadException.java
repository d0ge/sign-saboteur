package one.d4d.sessionless.itsdangerous;

public class BadPayloadException extends Exception{
    public BadPayloadException(String message) {
        super(message);
    }
}
