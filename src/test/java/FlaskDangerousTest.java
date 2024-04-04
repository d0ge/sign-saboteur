import one.d4d.signsaboteur.itsdangerous.crypto.DangerousTokenSigner;
import one.d4d.signsaboteur.itsdangerous.model.DangerousSignedToken;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class FlaskDangerousTest {
    @Test
    void DefaultFlaskSignedTokenTest() {
        byte[] secret = "secret".getBytes();
        byte[] salt = "cookie-session".getBytes();
        byte[] sep = new byte[]{(byte) '.'};
        DangerousSignedToken newToken = new DangerousSignedToken(sep, "{}", "Zzx63w", "");
        DangerousTokenSigner s = new DangerousTokenSigner(secret, salt, sep);
        newToken.setSigner(s);
        char[] signedToken = newToken.dumps().toCharArray();
        char[] testValue = "e30.Zzx63w.2BFIyJyE4fVqPm2hhw3edr8QTwo".toCharArray();
        assertArrayEquals(signedToken, testValue);
    }
}
