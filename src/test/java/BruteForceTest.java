import one.d4d.sessionless.itsdangerous.Attack;
import one.d4d.sessionless.itsdangerous.BruteForce;
import one.d4d.sessionless.itsdangerous.crypto.DangerousTokenSigner;
import one.d4d.sessionless.itsdangerous.model.SignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.sessionless.keys.SecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

public class BruteForceTest {

    @Test
    void BruteForceAttack() {
        Assertions.assertDoesNotThrow(() -> {
            Optional<SignedToken> optionalSignedToken = SignedTokenObjectFinder.parseToken("e30.Zm17Ig.Ajtll0l5CXAy9Yqgy-vvhF05G28");
            if (optionalSignedToken.isPresent()) {
                SignedToken token = optionalSignedToken.get();
                DangerousTokenSigner s = new DangerousTokenSigner((byte) '.');
                token.setSigner(s);
                final List<String> secrets = List.of("secret");
                final List<String> salts = List.of("salt");

                BruteForce bf = new BruteForce(secrets, salts, Attack.FAST, token);
                SecretKey sk = bf.search();
                Assertions.assertNotNull(sk);
            } else {
                Assertions.fail("Token not found.");
            }
        });
    }

    @Test
    void BruteForceMultiThreatAttack() {
        Assertions.assertDoesNotThrow(() -> {
            Optional<SignedToken> optionalSignedToken = SignedTokenObjectFinder.parseToken("e30.Zm17Ig.Ajtll0l5CXAy9Yqgy-vvhF05G28");
            if (optionalSignedToken.isPresent()) {
                SignedToken token = optionalSignedToken.get();
                DangerousTokenSigner s = new DangerousTokenSigner((byte) '.');
                token.setSigner(s);
                final List<String> secrets = List.of("secret");
                final List<String> salts = List.of("salt");

                BruteForce bf = new BruteForce(secrets, salts, Attack.FAST, token);
                SecretKey sk = bf.search();
                Assertions.assertNotNull(sk);
            } else {
                Assertions.fail("Token not found.");
            }
        });
    }

}
