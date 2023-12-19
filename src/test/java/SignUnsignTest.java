import one.d4d.sessionless.itsdangerous.*;
import one.d4d.sessionless.itsdangerous.crypto.DangerousTokenSigner;
import one.d4d.sessionless.itsdangerous.model.DangerousSignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

public class SignUnsignTest {
    @Test
    void KeyDerivationTest() {
        Assertions.assertDoesNotThrow(() -> {
            for(Algorithms a: Algorithms.values()){
                for(Derivation d: Derivation.values()){
                    byte[] secret = "secret".getBytes();
                    byte[] salt = "cookie-session".getBytes();
                    String ts = new String(Utils.timestampInFuture());
                    DangerousSignedToken newToken = new DangerousSignedToken((byte)'.',"{}",ts,"");
                    DangerousTokenSigner s = new DangerousTokenSigner(a,d,secret,salt,(byte)'.');
                    newToken.setSigner(s);
                    String signedToken = newToken.dumps();
                    Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseToken(signedToken);
                    if (optionalToken.isPresent()) {
                        SignedToken token = optionalToken.get();
                        token.setSigner(s);
                        final List<String> secrets = List.of("secret");
                        final List<String> salts = List.of("cookie-session");

                        BruteForce bf = new BruteForce(secrets, salts, Attack.Deep, token);
                        SecretKey sk = bf.search();
                        Assertions.assertNotNull(sk);
                    }

                }
            }
        });
    }
}
