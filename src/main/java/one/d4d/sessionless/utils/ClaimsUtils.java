package one.d4d.sessionless.utils;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.sessionless.itsdangerous.BadPayloadException;
import one.d4d.sessionless.itsdangerous.crypto.JSONWebSignatureTokenSigner;
import one.d4d.sessionless.itsdangerous.model.JSONWebSignature;
import one.d4d.sessionless.keys.SecretKey;

import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

public class ClaimsUtils {
    public static final String DEFAULT_USERNAME = "admin";
    public static final int DEFAULT_USERID = 1;
    public static final String DEFAULT_COLLABORATOR_URL = "http://localhost/";
    private static final long EXPIRE_TIME = 1000 * 60 * 60 * 24;

    public static JWTClaimsSet generateUserClaim(URL target) {
        return generateUserClaim(target, DEFAULT_USERNAME, DEFAULT_COLLABORATOR_URL);
    }
    public static JWTClaimsSet generateUserClaim(URL target, String collaborator) {
        return generateUserClaim(target, DEFAULT_USERNAME, collaborator);
    }

    public static JWTClaimsSet generateUserClaim(URL target, String username, String collaborator) {
        final long currentTimeMillis = System.currentTimeMillis();
        String host = target.getHost().equals("") ? "localhost" : target.getHost();

        return new JWTClaimsSet.Builder()
                .subject(String.format("%s@%s", username, host))
                .audience(target.getAuthority())
                .issuer(target.toString())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date(currentTimeMillis))
                .notBeforeTime(new Date(currentTimeMillis))
                .expirationTime(new Date(currentTimeMillis + EXPIRE_TIME))
                .claim("name", username)
                .claim("family_name", username)
                .claim("middle_name", username)
                .claim("given_name", username)
                .claim("nickname", username)
                .claim("preferred_username", String.format("%s@%s", username, host))
                .claim("email", String.format("%s@%s", username, host))
                .claim("email_verified", true)
                .claim("profile", collaborator)
                .claim("picture", collaborator)
                .claim("website", collaborator)
                .build();
    }

    public static JWTClaimsSet generateUserPayload(URL target) {
        JWTClaimsSet payload = generateUserClaim(target);
        return new JWTClaimsSet.Builder()
                .claim("user", payload.getClaims())
                .build();
    }

    public static JWTClaimsSet generateUserPasswordPayload(URL target) {
        return generateUserPasswordPayload(target, DEFAULT_USERNAME);
    }

    public static JWTClaimsSet generateUserPasswordPayload(URL target, String username) {
        return new JWTClaimsSet.Builder()
                .claim("username", username)
                .claim("password", "password")
                .claim("url", target.toString())
                .build();
    }

    public static JWTClaimsSet generateFlaskUserPayload(URL target) {
        return generateFlaskUserPayload(target, DEFAULT_USERID);
    }

    public static JWTClaimsSet generateFlaskUserPayload(URL target, int id) {
        return new JWTClaimsSet.Builder()
                .claim("_fresh", true)
                .claim("csrf", UUID.randomUUID().toString())
                .claim("locale", "en")
                .claim("user_logged", true)
                .claim("_id", id)
                .claim("_user_id", id)
                .claim("id", id)
                .claim("user_id", id)
                .claim("_permanent", true)
                .build();
    }

    public static JWTClaimsSet generateExpressUserPayload() {
        return generateExpressUserPayload(DEFAULT_USERNAME);
    }

    public static JWTClaimsSet generateExpressUserPayload(String username) {
        JWTClaimsSet passport = new JWTClaimsSet.Builder()
                .claim("user", username)
                .build();
        return new JWTClaimsSet.Builder()
                .claim("passport", passport.getClaims())
                .claim("flash", new Object())
                .build();
    }

    public static JWTClaimsSet generateAccountUserPayload(URL target) {
        return generateAccountUserPayload(target, DEFAULT_USERNAME);
    }

    public static JWTClaimsSet generateAccountUserPayload(URL target, String username) {
        String host = target.getHost().equals("") ? "localhost" : target.getHost();
        String email = String.format("%s@%s", username, host);
        JWTClaimsSet idTokenClaims = new JWTClaimsSet.Builder()
                .claim("name", username)
                .claim("emails", new String[]{email})
                .claim("preferred_username", email)
                .build();
        JWTClaimsSet account = new JWTClaimsSet.Builder()
                .claim("username", username)
                .claim("name", username)
                .claim("idTokenClaims", idTokenClaims.getClaims())
                .build();
        return new JWTClaimsSet.Builder()
                .claim("account", account.getClaims())
                .build();
    }

    public static JWTClaimsSet generateAuthenticatedClaims() {
        return new JWTClaimsSet.Builder()
                .claim("is_logined", true)
                .claim("loggedIn", true)
                .claim("isAuth", true)
                .claim("isAuthAdmin", true)
                .claim("isAuthenticated", true)
                .claim("isAdmin", true)
                .claim("isAdminLogged", true)
                .claim("isAdminLoggedIn", true)
                .claim("isLogin", true)
                .claim("isLogged", true)
                .claim("isLoggedIn", true)
                .claim("isUserLoggedIn", true)
                .build();
    }

    public static JWTClaimsSet concatClaims(List<JWTClaimsSet> args) throws ParseException {
        Map<String, Object> claims = new HashMap<>();
        for (JWTClaimsSet claim : args) {
            claims.putAll(claim.toJSONObject());
        }
        return JWTClaimsSet.parse(claims);
    }

    public static String generateJSONWebToken(URL target, String username, SecretKey key) throws BadPayloadException {
        try {
            JWSAlgorithm alg;
            switch (key.getDigestMethod()) {
                case SHA256 -> alg = JWSAlgorithm.HS256;
                case SHA384 -> alg = JWSAlgorithm.HS384;
                default -> alg = JWSAlgorithm.HS512;
            }
            final long currentTimeMillis = Instant.now().getEpochSecond();
            final long expirationTimeMillis = currentTimeMillis + EXPIRE_TIME;
            Payload payload = generateUserClaim(target, username).toPayload();
            JWSHeader header = new JWSHeader.Builder(alg)
                    .customParam("iat", currentTimeMillis)
                    .customParam("exp", expirationTimeMillis)
                    .build();
            JSONWebSignature token = new JSONWebSignature(header.toBase64URL().toString(), payload.toBase64URL().toString(), "", new byte[]{'.'});
            JSONWebSignatureTokenSigner signer = new JSONWebSignatureTokenSigner(key);
            token.setSigner(signer);
            token.resign();
            return token.serialize();
        } catch (Exception e) {
            throw new BadPayloadException("Payload error");
        }
    }

    public static JWTClaimsSet generateUserAccessTokenPayload(URL target, SecretKey key) {
        try {
            String payload = generateJSONWebToken(target, DEFAULT_USERNAME, key);
            return new JWTClaimsSet.Builder()
                    .claim("access_token", payload)
                    .build();
        } catch (Exception e) {
            return new JWTClaimsSet.Builder().build();
        }
    }

    public static JWTClaimsSet generateUserAccessTokenPayload(URL target, String username, SecretKey key) {
        try {
            String payload = generateJSONWebToken(target, username, key);
            return new JWTClaimsSet.Builder()
                    .claim("access_token", payload)
                    .build();
        } catch (Exception e) {
            return new JWTClaimsSet.Builder().build();
        }
    }

}
