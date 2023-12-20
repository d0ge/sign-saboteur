import com.google.common.collect.Lists;
import one.d4d.sessionless.itsdangerous.*;
import one.d4d.sessionless.itsdangerous.crypto.DjangoTokenSigner;
import one.d4d.sessionless.itsdangerous.model.UnknownSignedToken;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

public class UnknownSignedTokenTest {
    @Test
    void DjangoSignerTest() {
        byte[] secret = "secret".getBytes();
        byte[] salt = "django.core.signing.Signer".getBytes();
        String value = "eyJtZXNzYWdlIjoiSGVsbG8hIn0:V1O2qShdoisLMx2d0JTmVQecu8zsLPeXmTM5Id3ll-0";
        UnknownSignedToken token = new UnknownSignedToken(
                "eyJtZXNzYWdlIjoiSGVsbG8hIn0",
                "V1O2qShdoisLMx2d0JTmVQecu8zsLPeXmTM5Id3ll",
                (byte)':');
        DjangoTokenSigner s = new DjangoTokenSigner(Algorithms.SHA256, Derivation.DJANGO, MessageDigestAlgorithm.SHA256,secret, salt, (byte) ':');
        token.setSigner(s);
        Assertions.assertDoesNotThrow( ()-> {
            s.unsign(value.getBytes());
        });
    }

    @Test
    void DjangoSignedMessageSaltDictionaryTest() {
        String secret = "ybgcsl1^swnd1*shae^5mibuc3j4^sq(l(+qb&qj1k8aydfw)(";
        UnknownSignedToken token = new UnknownSignedToken(
                "My string",
                "prKofmME1ctlqPuuojYNv3CbncoQuwocwMTrG9_Viuw",
                (byte)':');
        final List<String> secrets = Utils.readResourceForClass("/secrets", this.getClass());
        final List<String> salts = Utils.readResourceForClass("/salts", this.getClass());
        secrets.add(secret);
        BruteForce bf = new BruteForce(secrets, salts, Attack.Balanced, token);
        SecretKey sk = bf.search();
        Assertions.assertNotNull(sk);
    }
    @Test
    void DjangoSignedMessageBruteForceTest() {
        String secret = "ybgcsl1^swnd1*shae^5mibuc3j4^sq(l(+qb&qj1k8aydfw)(";
        UnknownSignedToken token = new UnknownSignedToken(
                "hello:1rFgFX",
                "rpptBM3tbFJOZuNpSl_3wZwqHUGFsWlyY5ygIlsJOPA",
                (byte)':');
        final List<String> secrets = Utils.readResourceForClass("/secrets", this.getClass());
        final List<String> salts = Utils.readResourceForClass("/salts", this.getClass());
        secrets.add(secret);
        BruteForce bf = new BruteForce(secrets, salts, Attack.Balanced, token);
        SecretKey sk = bf.search();
        Assertions.assertNotNull(sk);
    }
    @Test
    void URLSafeSerializerTest() {
        UnknownSignedToken token = new UnknownSignedToken(
                "eyJpZCI6NSwibmFtZSI6Iml0c2Rhbmdlcm91cyJ9",
                "6YP6T0BaO67XP--9UzTrmurXSmg",
                (byte)'.');
        final List<String> secrets = Lists.newArrayList("secret key");
        final List<String> salts = Lists.newArrayList("auth");
        BruteForce bf = new BruteForce(secrets, salts, Attack.Balanced, token);
        SecretKey sk = bf.search();
        Assertions.assertNotNull(sk);
    }
    @Test
    void ItsDangerousSignerTest() {
        UnknownSignedToken token = new UnknownSignedToken(
                "my string",
                "wh6tMHxLgJqB6oY1uT73iMlyrOA",
                (byte)'.');
        final List<String> secrets = Lists.newArrayList("secret-key");
        final List<String> salts = Lists.newArrayList("itsdangerous.Signer");
        BruteForce bf = new BruteForce(secrets, salts, Attack.Balanced, token);
        SecretKey sk = bf.search();
        Assertions.assertNotNull(sk);
    }
    @Test
    void RedashURLSafeTimedSerializerTest() {
        UnknownSignedToken token = new UnknownSignedToken(
                "IjEi.YhAmmQ",
                "cdQp7CnnVq02aQ05y8tSBddl-qs",
                (byte)'.');
        final List<String> secrets = Lists.newArrayList("c292a0a3aa32397cdb050e233733900f");
        final List<String> salts = Lists.newArrayList("itsdangerous");
        BruteForce bf = new BruteForce(secrets, salts, Attack.Balanced, token);
        SecretKey sk = bf.search();
        Assertions.assertNotNull(sk);
    }
}
