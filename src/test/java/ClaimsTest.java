import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.signsaboteur.itsdangerous.Algorithms;
import one.d4d.signsaboteur.itsdangerous.Derivation;
import one.d4d.signsaboteur.itsdangerous.MessageDerivation;
import one.d4d.signsaboteur.itsdangerous.MessageDigestAlgorithm;
import one.d4d.signsaboteur.keys.SecretKey;
import one.d4d.signsaboteur.utils.ClaimsUtils;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

public class ClaimsTest {
    @Test
    void UserClaimTest() {
        try {
            URL target = new URL("https://d4d.one/");
            ClaimsUtils.generateUserClaim(target);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
    @Test
    void BasicUserPayloadTest() {
        try {
            URL target = new URL("https://d4d.one/");
            ClaimsUtils.generateUserPayload(target);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
    @Test
    void FlaskUserPayloadTest() {
        try {
            URL target = new URL("https://d4d.one/");
            ClaimsUtils.generateFlaskUserPayload(target, 1337);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
    @Test
    void ExpressUserPayloadTest() {
        ClaimsUtils.generateExpressUserPayload();
    }

    @Test
    void ClaimsJoinerTest() {
        try {
            URL target = new URL("https://d4d.one/");
            List<JWTClaimsSet> args = new ArrayList<>();
            args.add(ClaimsUtils.generateUserClaim(target));
            args.add(ClaimsUtils.generateAuthenticatedClaims());
            ClaimsUtils.concatClaims(args);
        } catch (MalformedURLException|ParseException e) {
            throw new RuntimeException(e);
        }
    }
    @Test
    void AccountUserPayloadTest() {
        try {
            URL target = new URL("https://d4d.one/");
            ClaimsUtils.generateAccountUserPayload(target);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
    @Test
    void UserAccessTokenPayloadTest() {
        try {
            SecretKey key = new SecretKey(
                    "1",
                    "secret",
                    "",
                    ".",
                    Algorithms.SHA256,
                    Derivation.NONE,
                    MessageDerivation.NONE,
                    MessageDigestAlgorithm.NONE);
            URL target = new URL("https://d4d.one/");
            ClaimsUtils.generateUserAccessTokenPayload(target, key);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

}
