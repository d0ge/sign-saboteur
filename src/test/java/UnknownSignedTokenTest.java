import one.d4d.sessionless.itsdangerous.*;
import one.d4d.sessionless.itsdangerous.crypto.DjangoTokenSigner;
import one.d4d.sessionless.itsdangerous.model.SignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.sessionless.itsdangerous.model.UnknownSignedToken;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.*;

public class UnknownSignedTokenTest {
    @Test
    void DjangoSignerTest() {
        byte[] secret = "secret".getBytes();
        byte[] salt = "django.core.signing.Signer".getBytes();
        byte[] sep = new byte[]{(byte) ':'};
        String value = "eyJtZXNzYWdlIjoiSGVsbG8hIn0:V1O2qShdoisLMx2d0JTmVQecu8zsLPeXmTM5Id3ll-0";
        UnknownSignedToken token = new UnknownSignedToken(
                "eyJtZXNzYWdlIjoiSGVsbG8hIn0",
                "V1O2qShdoisLMx2d0JTmVQecu8zsLPeXmTM5Id3ll",
                sep);
        DjangoTokenSigner s = new DjangoTokenSigner(Algorithms.SHA256, Derivation.DJANGO, MessageDerivation.NONE, MessageDigestAlgorithm.SHA256, secret, salt, sep);
        token.setSigner(s);
        Assertions.assertDoesNotThrow(() -> {
            s.unsign(value.getBytes());
        });
    }

    @Test
    void DjangoSignedMessageSaltDictionaryTest() {
        String secret = "ybgcsl1^swnd1*shae^5mibuc3j4^sq(l(+qb&qj1k8aydfw)(";
        byte[] sep = new byte[]{(byte) ':'};
        UnknownSignedToken token = new UnknownSignedToken(
                "My string",
                "prKofmME1ctlqPuuojYNv3CbncoQuwocwMTrG9_Viuw",
                sep);
        final Set<String> secrets = Utils.readResourceForClass("/secrets", this.getClass());
        final Set<String> salts = Utils.readResourceForClass("/salts", this.getClass());
        final List<SecretKey> knownKeys = new ArrayList<>();
        secrets.add(secret);
        BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Balanced, token);
        SecretKey sk = bf.parallel();
        Assertions.assertNotNull(sk);
    }

    @Test
    void DjangoSignedMessageBruteForceTest() {
        String secret = "ybgcsl1^swnd1*shae^5mibuc3j4^sq(l(+qb&qj1k8aydfw)(";
        byte[] sep = new byte[]{(byte) ':'};
        UnknownSignedToken token = new UnknownSignedToken(
                "hello:1rFgFX",
                "rpptBM3tbFJOZuNpSl_3wZwqHUGFsWlyY5ygIlsJOPA",
                sep);
        final Set<String> secrets = Utils.readResourceForClass("/secrets", this.getClass());
        final Set<String> salts = Utils.readResourceForClass("/salts", this.getClass());
        final List<SecretKey> knownKeys = new ArrayList<>();
        secrets.add(secret);
        BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Balanced, token);
        SecretKey sk = bf.parallel();
        Assertions.assertNotNull(sk);
    }

    @Test
    void URLSafeSerializerTest() {
        byte[] sep = new byte[]{(byte) '.'};
        UnknownSignedToken token = new UnknownSignedToken(
                "eyJpZCI6NSwibmFtZSI6Iml0c2Rhbmdlcm91cyJ9",
                "6YP6T0BaO67XP--9UzTrmurXSmg",
                sep);
        final Set<String> secrets = new HashSet<>(List.of("secret key"));
        final Set<String> salts = new HashSet<>(List.of("auth"));
        final List<SecretKey> knownKeys = new ArrayList<>();
        BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Balanced, token);
        SecretKey sk = bf.parallel();
        Assertions.assertNotNull(sk);
    }

    @Test
    void ItsDangerousSignerTest() {
        byte[] sep = new byte[]{(byte) '.'};
        UnknownSignedToken token = new UnknownSignedToken(
                "my string",
                "wh6tMHxLgJqB6oY1uT73iMlyrOA",
                sep);
        final Set<String> secrets = new HashSet<>(List.of("secret-key"));
        final Set<String> salts = new HashSet<>(List.of("itsdangerous.Signer"));
        final List<SecretKey> knownKeys = new ArrayList<>();
        BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Balanced, token);
        SecretKey sk = bf.parallel();
        Assertions.assertNotNull(sk);
    }

    @Test
    void RedashURLSafeTimedSerializerTest() {
        byte[] sep = new byte[]{(byte) '.'};
        UnknownSignedToken token = new UnknownSignedToken(
                "IjEi.YhAmmQ",
                "cdQp7CnnVq02aQ05y8tSBddl-qs",
                sep);
        final Set<String> secrets = new HashSet<>(List.of("c292a0a3aa32397cdb050e233733900f"));
        final Set<String> salts = new HashSet<>(List.of("itsdangerous"));
        final List<SecretKey> knownKeys = new ArrayList<>();
        BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Balanced, token);
        SecretKey sk = bf.parallel();
        Assertions.assertNotNull(sk);
    }

    @Test
    void UnknownSignedStringParserTest() {
        final Set<String> secrets = new HashSet<>(List.of("c292a0a3aa32397cdb050e233733900f"));
        final Set<String> salts = new HashSet<>(List.of("itsdangerous"));
        final List<SecretKey> knownKeys = new ArrayList<>();
        String value = "IjEi.YhAmmQ.cdQp7CnnVq02aQ05y8tSBddl-qs";
        Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseUnknownSignedString(value);
        if (optionalToken.isPresent()) {
            UnknownSignedToken token = (UnknownSignedToken) optionalToken.get();
            BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Balanced, token);
            SecretKey sk = bf.parallel();
            Assertions.assertNotNull(sk);
        } else {
            Assertions.fail("Token not found.");
        }
    }
}
