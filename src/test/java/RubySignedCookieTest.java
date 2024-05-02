import one.d4d.signsaboteur.itsdangerous.Attack;
import one.d4d.signsaboteur.itsdangerous.BruteForce;
import one.d4d.signsaboteur.itsdangerous.model.RubySignedToken;
import one.d4d.signsaboteur.keys.SecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class RubySignedCookieTest {

    @Test
    void UnknownSignedRubySessionCookie() {
        try {
            String secret = "aeb977de013ade650b97e0aa5246813591104017871a7753fe186e9634c9129b367306606878985c759ca4fddd17d955207011bb855ef01ed414398b4ac8317b";
            String message = "WVFQVTFtbmNxWWJPODZNb3NUMVZzZGtDVjZQNXpMYStFMWdiZlJPMkdjRFRBOGZ5T3pOTzBPKzk3NWxvQUJvTlRRU2t4MXZmdG8rT0I0R2M3Ulh0YXpxRVhNMll5UW1xUHhvVXBLbXozZ3ZyNjB4VDU4dWRIUkxBWjBXbDJhci93YkYrZWswUHdFL0hUNDJaUHo2cEpxbXFvdlFZMjJWVU9KTWhHb3NyalFwTkphd0pUQVZSTXRHbkVqRlFnSGpNVTNFQlVxYlRmT3pWbXNjK0JuQ3FydzQvODRhbmtuU29haGNRbXQ4T3o1ZjhqMk53WTRMa0pVd1hPb2NHTVFQY3dvanE2ZElqUk1Mc21HS0k2SHVuZEZ3OWhjdzZPQnRSMEdVVkQwL2IxSVh5QzNSWVlJZms5c1JJV0lzUE1Zb1NHbEtqYm5nTGRKd1ZSdGpOQ1RZZWthR1A2anRFMEluaTcyWTNaNHJBR1N0dklzMkg1RjVmVmY4azEzV3o0N2Z2LS1wQlowRUZ6cjI3SVFQU0F5bGlYSDNnPT0=";
            String signature = "19650cc5c3e2599fb43b7235ab4de5a1ce8a46ac";
            RubySignedToken token = new RubySignedToken(message, signature, false);
            final Set<String> secrets = new HashSet<>(List.of(secret));
            final Set<String> salts = new HashSet<>(List.of("signed encrypted cookie"));
            final List<SecretKey> knownKeys = new ArrayList<>();
            BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.FAST, token);
            SecretKey sk = bf.parallel();
            Assertions.assertNotNull(sk);
        } catch (Exception e) {
            Assertions.fail("Token not found.");
        }
    }

    @Test
    void UnknownSignedDefaultRubySessionCookie() {
        try {
            String secret = "aeb977de013ade650b97e0aa5246813591104017871a7753fe186e9634c9129b367306606878985c759ca4fddd17d955207011bb855ef01ed414398b4ac8317b";
            String message = "cE5HNFl3QlUxVUxsMkdmNjVKaGJ3YkkvNEVxQ0xmenZ5dENzejdPYWpJTT0tLVcxZXlSSWxLS1hqcE4rMmhuNU5nVUE9PQ==";
            String signature = "7e6628b1f383f447b6feac19c2363083a9998d9e";
            RubySignedToken token = new RubySignedToken(message, signature);
            final Set<String> secrets = new HashSet<>(List.of(secret));
            final Set<String> salts = new HashSet<>(List.of("signed encrypted cookie"));
            final List<SecretKey> knownKeys = new ArrayList<>();
            BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Deep, token);
            SecretKey sk = bf.parallel();
            Assertions.assertNotNull(sk);
        } catch (Exception e) {
            Assertions.fail("Token not found.");
        }
    }

    @Test
    void UnknownSignedDefaultRubyMessageVerifier() {
        try {
            String secret = "aeb977de013ade650b97e0aa5246813591104017871a7753fe186e9634c9129b367306606878985c759ca4fddd17d955207011bb855ef01ed414398b4ac8317b";
            String message = "BAhJIhNteSBzZWNyZXQgZGF0YQY6BkVU";
            String signature = "578b70deb080dbe07538ab86198ab19819d6a310";
            RubySignedToken token = new RubySignedToken(message, signature);
            final Set<String> secrets = new HashSet<>(List.of(secret));
            final Set<String> salts = new HashSet<>(List.of("signed encrypted cookie"));
            final List<SecretKey> knownKeys = new ArrayList<>();
            BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Deep, token);
            SecretKey sk = bf.parallel();
            Assertions.assertNotNull(sk);
        } catch (Exception e) {
            Assertions.fail("Token not found.");
        }
    }

    @Test
    void UnknownSignedDefaultRubySessionCookie32() {
        try {
            String secret = "aeb977de013ade650b97e0aa5246813591104017871a7753fe186e9634c9129b367306606878985c759ca4fddd17d955207011bb855ef01ed414398b4ac8317b";
            String message = "NWU3YXRTS3RsSXRZcHBoMlJrNW9DOWlxSGpaWEFzbnM5UzBCUExMNDkwbz0tLXRDOWpQMHVCK055cmNXcDJGRXppZmc9PQ==";
            String signature = "5112fc6a45589e07bda0916670a67053366d09d3";
            RubySignedToken token = new RubySignedToken(message, signature);
            final Set<String> secrets = new HashSet<>(List.of(secret));
            final Set<String> salts = new HashSet<>(List.of("signed encrypted cookie"));
            final List<SecretKey> knownKeys = new ArrayList<>();
            BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Deep, token);
            SecretKey sk = bf.parallel();
            Assertions.assertNotNull(sk);
        } catch (Exception e) {
            Assertions.fail("Token not found.");
        }
    }

    @Test
    void ActiveStorageBlobTest() {
        String secret = "645deb7dc7a12794104f5dbc61ae22037cd9b1def6a8ea4becb3761349a32d483717d56b91bd7e95a9190f4cab6ffa5f118baacf08ac3e1bc4a7a2c186011653";
        String salt = "ActiveStorage";
        String message = "eyJfcmFpbHMiOnsiZGF0YSI6eyJrZXkiOiJ2bnhzNmZsb2tpMWxhNjVkeTl3ODkwc2tzMHFhIiwiZGlzcG9zaXRpb24iOiJhdHRhY2htZW50OyBmaWxlbmFtZT1cInNlY3JldC50eHRcIjsgZmlsZW5hbWUqPVVURi04JydzZWNyZXQudHh0IiwiY29udGVudF90eXBlIjoidGV4dC9wbGFpbiIsInNlcnZpY2VfbmFtZSI6ImxvY2FsIn0sImV4cCI6IjIwMjQtMDQtMjRUMTY6MjQ6MzUuMjMzWiIsInB1ciI6ImJsb2Jfa2V5In19";
        String signature = "f8634de8f4826b3c4f067f883cc3fc360e99b35e";
        RubySignedToken token = new RubySignedToken(message, signature);
        final Set<String> secrets = new HashSet<>(List.of(secret));
        final Set<String> salts = new HashSet<>(List.of(salt));
        final List<SecretKey> knownKeys = new ArrayList<>();
        BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.FAST, token);
        SecretKey sk = bf.parallel();
        Assertions.assertNotNull(sk);
     }
}
