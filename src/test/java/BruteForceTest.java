import one.d4d.signsaboteur.itsdangerous.Attack;
import one.d4d.signsaboteur.itsdangerous.BruteForce;
import one.d4d.signsaboteur.itsdangerous.crypto.DangerousTokenSigner;
import one.d4d.signsaboteur.itsdangerous.model.SignedToken;
import one.d4d.signsaboteur.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.signsaboteur.keys.SecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.*;

public class BruteForceTest {

    @Test
    void BruteForceAttack() {
        Assertions.assertDoesNotThrow(() -> {
            Optional<SignedToken> optionalSignedToken = SignedTokenObjectFinder.parseToken("e30.Zm17Ig.Ajtll0l5CXAy9Yqgy-vvhF05G28");
            if (optionalSignedToken.isPresent()) {
                SignedToken token = optionalSignedToken.get();
                byte[] sep = new byte[]{'.'};
                DangerousTokenSigner s = new DangerousTokenSigner(sep);
                token.setSigner(s);
                final Set<String> secrets = new HashSet<>(List.of("secret"));
                final Set<String> salts = new HashSet<>(List.of("salt"));
                final List<SecretKey> knownKeys = new ArrayList<>();

                BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.FAST, token);
                SecretKey sk = bf.parallel();
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
                byte[] sep = new byte[]{'.'};
                DangerousTokenSigner s = new DangerousTokenSigner(sep);
                token.setSigner(s);
                final Set<String> secrets = new HashSet<>(List.of("secret"));
                final Set<String> salts = new HashSet<>(List.of("salt"));
                final List<SecretKey> knownKeys = new ArrayList<>();

                BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.FAST, token);
                SecretKey sk = bf.parallel();
                Assertions.assertNotNull(sk);
            } else {
                Assertions.fail("Token not found.");
            }
        });
    }

}
