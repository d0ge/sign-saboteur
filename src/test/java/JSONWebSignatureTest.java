import one.d4d.sessionless.itsdangerous.*;
import one.d4d.sessionless.itsdangerous.model.JSONWebSignature;
import one.d4d.sessionless.itsdangerous.model.SignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.ClaimsUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Optional;

public class JSONWebSignatureTest {
    @Test
    void JSONWebSignatureParserTest() {
        final List<String> secrets = List.of("your-256-bit-secret");
        final List<String> salts = List.of("salt");
        String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseJSONWebSignature(value);
        if (optionalToken.isPresent()) {
            JSONWebSignature token = (JSONWebSignature) optionalToken.get();
            BruteForce bf = new BruteForce(secrets, salts, Attack.FAST, token);
            SecretKey sk = bf.search();
            Assertions.assertNotNull(sk);
        } else {
            Assertions.fail("Token not found.");
        }
    }
    @Test
    void JSONWebSignatureClaimsTest() {
        try {
            final List<String> secrets = List.of("secret");
            final List<String> salts = List.of("salt");
            URL target = new URL("https://d4d.one/");
            SecretKey key = new SecretKey("1", "secret", "",".", Algorithms.SHA256, Derivation.NONE, MessageDigestAlgorithm.NONE);
            String value = ClaimsUtils.generateJSONWebToken(target, ClaimsUtils.DEFAULT_USERNAME, key);
            Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseJSONWebSignature(value);
            if (optionalToken.isPresent()) {
                JSONWebSignature token = (JSONWebSignature) optionalToken.get();
                BruteForce bf = new BruteForce(secrets, salts, Attack.FAST, token);
                SecretKey sk = bf.search();
                Assertions.assertNotNull(sk);
            } else {
                Assertions.fail("Token not found.");
            }
        } catch (MalformedURLException | BadPayloadException e) {
            throw new RuntimeException(e);
        }
    }
}
