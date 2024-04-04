package one.d4d.signsaboteur.itsdangerous;

public class BadSignatureException extends Exception{
    public BadSignatureException(String message) {
        super(message);
    }
}
