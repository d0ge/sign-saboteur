import one.d4d.signsaboteur.itsdangerous.crypto.OauthProxyTokenSigner;
import one.d4d.signsaboteur.itsdangerous.model.OauthProxySignedToken;
import one.d4d.signsaboteur.itsdangerous.model.SignedToken;
import one.d4d.signsaboteur.itsdangerous.model.SignedTokenObjectFinder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Optional;

public class OAuth2Test {
    @Test
    void OauthProxyParserTest() {
        byte[] secret = "j76h5PEMx3FIGr3caArJ5g==".getBytes();
        byte[] sep = new byte[]{(byte) '|'};
        OauthProxyTokenSigner s = new OauthProxyTokenSigner(secret, sep);
        String key = "_oauth2_proxy_csrf";
        String value = "hVV2htpqQw4UXgsLYtKdAWct1VAg_yPMxjq2xrGaaCfZStG0p6sGjlAGim1a686QrbBgDGNnpr6LrKH88uTQpTMHLiknn-YbVnXsbFtRyciE5QJIk3q8t24=|1688047283|MFrbdc2q8uQSZd9bpfaWWAmfkHY3U4mijmQo-vqMRKw=";
        Optional<SignedToken> optionalSignedToken = SignedTokenObjectFinder.parseOauthProxySignedToken(key, value);
        if (optionalSignedToken.isPresent()) {
            OauthProxySignedToken token = (OauthProxySignedToken) optionalSignedToken.get();
            token.setSigner(s);
            Assertions.assertDoesNotThrow(() -> {
                s.unsign(String.format("%s|%s", key, value).getBytes());
            });
        } else {
            Assertions.fail("Token not found.");
        }
    }
}
