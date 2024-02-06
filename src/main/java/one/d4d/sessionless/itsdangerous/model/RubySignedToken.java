package one.d4d.sessionless.itsdangerous.model;

import burp.config.Signers;
import one.d4d.sessionless.itsdangerous.crypto.RubyTokenSigner;
import one.d4d.sessionless.utils.HexUtils;

public class RubySignedToken extends UnknownSignedToken {

    public RubySignedToken(String message, String signature) {
        this(message, signature, "--".getBytes());
    }

    public RubySignedToken(String message, String signature, byte[] separator) {
        super(message, signature, separator);
        this.signer = new RubyTokenSigner(separator);
    }

    @Override
    public void resign() throws Exception {
        this.signature = HexUtils.encodeHex(signer.get_signature_unsafe(message.getBytes()));
    }

    @Override
    public String getSignersName() {
        return Signers.RUBY.name();
    }

}
