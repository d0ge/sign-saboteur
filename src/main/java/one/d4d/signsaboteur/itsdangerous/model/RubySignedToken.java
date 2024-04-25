package one.d4d.signsaboteur.itsdangerous.model;

import one.d4d.signsaboteur.itsdangerous.crypto.RubyTokenSigner;
import one.d4d.signsaboteur.itsdangerous.crypto.Signers;
import one.d4d.signsaboteur.utils.HexUtils;

public class RubySignedToken extends UnknownSignedToken {

    public RubySignedToken(String message, String signature) {
        this(message, signature, "--".getBytes(), false);
    }
    public RubySignedToken(String message, String signature, boolean isURLEncoded) {
        this(message, signature, "--".getBytes(), isURLEncoded);
    }

    public RubySignedToken(String message, String signature, byte[] separator, boolean isURLEncoded) {
        super(message, signature, separator, isURLEncoded);
        this.signer = new RubyTokenSigner(separator);
    }

    @Override
    public void resign() throws Exception {
        this.signature = HexUtils.encodeHex(signer.get_signature_unsafe(message.getBytes()));
    }

    @Override
    public String getEncodedSignature() {
        return signature.toLowerCase();
    }

    @Override
    public String getSignersName() {
        return Signers.RUBY.name();
    }

}
