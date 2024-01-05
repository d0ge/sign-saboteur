package one.d4d.sessionless.itsdangerous;

import one.d4d.sessionless.itsdangerous.crypto.TokenSigner;
import one.d4d.sessionless.itsdangerous.model.SignedToken;
import one.d4d.sessionless.itsdangerous.model.UnknownSignedToken;
import one.d4d.sessionless.keys.SecretKey;

import java.util.ArrayList;
import java.util.List;

public class BruteForce {
    private final List<String> secrets;
    private final List<String> salts;
    private final List<SecretKey> signingKeys;
    private final Attack scanConfiguration;
    private final SignedToken token;

    public BruteForce(List<String> secrets, List<String> salts, List<SecretKey> signingKeys, Attack scanConfiguration, SignedToken token) {
        this.secrets = secrets;
        this.salts = salts;
        this.signingKeys = signingKeys;
        this.scanConfiguration = scanConfiguration;
        this.token = token;
    }

    public List<TokenSigner> prepare() {
        List<TokenSigner> attacks = new ArrayList<>();
        TokenSigner is = token.getSigner();
        if (scanConfiguration == Attack.KNOWN) {
            this.signingKeys.forEach(key -> {
                TokenSigner ks = new TokenSigner(key);
                attacks.add(ks);
            });
            return attacks;
        }
        for (String secret : secrets) {
            if (scanConfiguration == Attack.FAST) {
                if (is.getKeyDerivation() == Derivation.NONE) {
                    TokenSigner s = is.clone();
                    s.setSecretKey(secret.getBytes());
                    attacks.add(s);
                } else {
                    for (String salt : salts) {
                        TokenSigner s = is.clone();
                        s.setSecretKey(secret.getBytes());
                        s.setSalt(salt.getBytes());
                        attacks.add(s);
                    }
                }
            } else {
                for (MessageDerivation md : MessageDerivation.values()) {
                    if(md != MessageDerivation.NONE && !(token instanceof UnknownSignedToken)) continue;
                    for (Derivation d : Derivation.values()) {
                        if (d == Derivation.NONE) {
                            TokenSigner s = is.clone();
                            s.setKeyDerivation(d);
                            s.setMessageDerivation(md);
                            s.setSecretKey(secret.getBytes());
                            attacks.add(s);
                        } else if (d == Derivation.HASH) {
                            for (MessageDigestAlgorithm m : MessageDigestAlgorithm.values()) {
                                TokenSigner s = is.clone();
                                s.setKeyDerivation(d);
                                s.setMessageDerivation(md);
                                s.setSecretKey(secret.getBytes());
                                s.setMessageDigestAlgorithm(m);
                                attacks.add(s);
                            }
                        } else {
                            if (d == Derivation.PBKDF2HMAC && scanConfiguration != Attack.Deep) continue;
                            for (MessageDigestAlgorithm m : MessageDigestAlgorithm.values()) {
                                for (String salt : salts) {
                                    TokenSigner s = is.clone();
                                    s.setKeyDerivation(d);
                                    s.setMessageDerivation(md);
                                    s.setSecretKey(secret.getBytes());
                                    s.setSalt(salt.getBytes());
                                    s.setMessageDigestAlgorithm(m);
                                    attacks.add(s);
                                }
                            }
                        }
                    }
                }
            }
        }
        return attacks;
    }

    public SecretKey search() {
        List<TokenSigner> attacks = prepare();
        byte[] message = token.getEncodedMessage().getBytes();
        byte[] signature = token.getEncodedSignature().getBytes();
        for (TokenSigner s : attacks) {
            try {
                s.fast_unsign(message, signature);
                return s.getKey();
            } catch (BadSignatureException ignored) {
            }
        }
        return null;
    }

}
