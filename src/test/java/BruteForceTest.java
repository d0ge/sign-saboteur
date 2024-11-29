import one.d4d.signsaboteur.itsdangerous.Attack;
import one.d4d.signsaboteur.itsdangerous.BruteForce;
import one.d4d.signsaboteur.itsdangerous.crypto.DangerousTokenSigner;
import one.d4d.signsaboteur.itsdangerous.crypto.RubyEncryptionTokenSigner;
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

    @Test
    void encryptionTest() {
        String secret = "aeb977de013ade650b97e0aa5246813591104017871a7753fe186e9634c9129b367306606878985c759ca4fddd17d955207011bb855ef01ed414398b4ac8317b";
        String salt = "authenticated encrypted cookie";
        String app_session = "isteTiyNSFdbUoabLodAVDd4jQuj%2F5t%2FRTE6BqyklssH0ye%2F2RnMJ3fIBkFfr9tei5yh5agfgX%2F9Mi8gQIA4zAOXwGyCuJBhauvszTYDCW7Q%2FVwDXIc4lAtiO%2FmBf5txRBoAulkc4ZTAaT1FMM%2F6ky7p8oul0hbi4xZf1%2ByURhPci4f%2FEGNYsJ2eLx9BALX7sVOB3dYpN6eQb%2B7LTXRxy2bnObmiHQaNaTx6jhdWwRcdEgGph7le6dN49gi%2FiLp%2B0yecWNyEzQbZ%2FRHKniIf%2FmCFTVw%3D--e7EBPhAdylQsT6It--wIte3m%2F2WUhtfKQewysoSQ%3D%3D";

        Assertions.assertDoesNotThrow(() -> {
            Optional<SignedToken> optionalSignedToken = SignedTokenObjectFinder.parseRubyEncryptedToken("",app_session);
            if (optionalSignedToken.isPresent()) {
                SignedToken token = optionalSignedToken.get();
                byte[] sep = new byte[]{'-','-'};
                RubyEncryptionTokenSigner s = new RubyEncryptionTokenSigner(sep);
                token.setSigner(s);
                final Set<String> secrets = new HashSet<>(List.of(secret));
                final Set<String> salts = new HashSet<>(List.of(salt));
                final List<SecretKey> knownKeys = new ArrayList<>();

                BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.FAST, token);
                SecretKey sk = bf.parallel();
                Assertions.assertNotNull(sk);
                RubyEncryptionTokenSigner ns = new RubyEncryptionTokenSigner(sk);
                System.out.println(sk.toJSONString());
                token.setSigner(ns);
                token.resign();
                System.out.println(token);
            } else {
                Assertions.fail("Token not found.");
            }
        });
    }

}
