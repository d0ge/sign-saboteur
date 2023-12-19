package one.d4d.sessionless.itsdangerous;

public class BadSignatureException extends Exception{
    public BadSignatureException(String message) {
        super(message);
    }
}
