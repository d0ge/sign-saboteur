import one.d4d.signsaboteur.itsdangerous.*;
import one.d4d.signsaboteur.itsdangerous.crypto.DangerousTokenSigner;
import one.d4d.signsaboteur.itsdangerous.model.DangerousSignedToken;
import one.d4d.signsaboteur.itsdangerous.model.SignedToken;
import one.d4d.signsaboteur.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.signsaboteur.keys.SecretKey;
import one.d4d.signsaboteur.utils.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.*;

public class SignUnsignTest {
    @Test
    @Tag("slow")
    void KeyDerivationTest() {
        Assertions.assertDoesNotThrow(() -> {
            long start = System.currentTimeMillis();
            for (Algorithms a : Algorithms.values()) {
                for (Derivation d : Derivation.values()) {
                    for (MessageDerivation md : MessageDerivation.values()) {
                        for (MessageDigestAlgorithm mda : MessageDigestAlgorithm.values()) {
                            byte[] secret = "secret".getBytes();
                            byte[] salt = "cookie-session".getBytes();
                            byte[] sep = new byte[]{(byte) '.'};
                            String ts = new String(Utils.timestampInFuture());
                            DangerousSignedToken newToken = new DangerousSignedToken(sep, "{}", ts, "");
                            DangerousTokenSigner s = new DangerousTokenSigner(a, d, md, mda, secret, salt, sep);
                            newToken.setSigner(s);
                            String signedToken = newToken.dumps();
                            Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseToken(signedToken);
                            if (optionalToken.isPresent()) {
                                SignedToken token = optionalToken.get();
                                token.setSigner(s);
                                final Set<String> secrets = new HashSet<>(List.of("secret"));
                                final Set<String> salts = new HashSet<>(List.of("cookie-session"));
                                final List<SecretKey> knownKeys = new ArrayList<>();

                                BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Deep, token);
                                SecretKey sk = bf.parallel();
                                System.out.println(sk.toJSONString());
                                Assertions.assertNotNull(sk);
                            }
                        }
                    }
                }
            }
            long end = System.currentTimeMillis() - start;
            System.out.printf("Task finished in %.0f seconds", end / 1000.0);
        });
    }
}
