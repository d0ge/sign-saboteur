package one.d4d.sessionless.itsdangerous.model;

public class MutableSignedToken {
    private final String original;
    private SignedToken modified;

    public MutableSignedToken(String original, SignedToken modified) {
        this.original = original;
        this.modified = modified;
    }

    public boolean cracked() {
        return modified.getKey() != null;
    }

    public boolean changed() {
        return !original.equals(modified.serialize());
    }

    public void setModified(SignedToken o) {
        modified = o;
    }

    public SignedToken getModified() {
        return modified;
    }

    public String getOriginal() {
        return original;
    }
}
