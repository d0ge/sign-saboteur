package one.d4d.signsaboteur.itsdangerous.model;

import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.signsaboteur.itsdangerous.*;
import one.d4d.signsaboteur.itsdangerous.crypto.RubyEncryptionTokenSigner;
import one.d4d.signsaboteur.itsdangerous.crypto.RubyTokenSigner;
import one.d4d.signsaboteur.itsdangerous.crypto.Signers;
import one.d4d.signsaboteur.itsdangerous.crypto.TokenSigner;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class RubyEncryptedToken extends SignedToken {
    public byte[] separator;
    public boolean isURLEncoded;

    public RubyEncryptedToken(String message, String signature) {
        this(message, signature, "--".getBytes(), false);
    }
    public RubyEncryptedToken(String message, String signature, boolean isURLEncoded) {
        this(message, signature, "--".getBytes(), isURLEncoded);
    }

    public RubyEncryptedToken(String message, String signature, byte[] separator, boolean isURLEncoded) {
        super(message);
        this.signature = signature;
        this.separator = separator;
        this.isURLEncoded = isURLEncoded;
        this.signer = new RubyEncryptionTokenSigner(
                Algorithms.SHA256,
                Derivation.RUBY_ENCRYPTION,
                MessageDerivation.NONE,
                MessageDigestAlgorithm.NONE,
                new byte[]{},
                new byte[]{},
                separator);
    }

    @Override
    public String serialize() {
        String raw = String.format("%s%s%s", message, new String(separator), signature);
        return isURLEncoded ? URLEncoder.encode(raw, StandardCharsets.UTF_8) : raw;
    }

    @Override
    public void resign() throws Exception {
        try {
            byte[] decrypted = this.signer.fast_unsign(message.getBytes(StandardCharsets.UTF_8), signature.getBytes(StandardCharsets.UTF_8));
            String encrypted = new String(this.signer.sign(decrypted));
            this.message = encrypted.substring(0, encrypted.lastIndexOf("--"));
            this.signature = encrypted.substring(encrypted.lastIndexOf("--") + 2);
        }catch (BadSignatureException ignored) {
        }
    }

    @Override
    public void setClaims(JWTClaimsSet claims) {

    }

    public String getCypherText() {
        try {
            return new String(this.signer.fast_unsign(message.getBytes(StandardCharsets.UTF_8), signature.getBytes(StandardCharsets.UTF_8)));
        } catch (BadSignatureException e) {
            return "Error";
        }
    }

    public void setCypherText(String text) {
        String encrypted = new String(this.signer.sign(text.getBytes(StandardCharsets.UTF_8)));
        this.message = encrypted.substring(0, encrypted.lastIndexOf("--"));
        this.signature = encrypted.substring(encrypted.lastIndexOf("--") + 2);
    }

    public boolean isURLEncoded() { return isURLEncoded;}

    public String getSignersName() {
        return Signers.ENCRYPTION.name();
    }

    public byte[] getSeparator() {
        return separator;
    }

    public void setSeparator(byte[] separator) {
        this.separator = separator;
    }
}
