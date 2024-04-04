import one.d4d.signsaboteur.utils.Utils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class TimestampTest {
    @Test
    void Base64EncodedTimestampTest() {
        String expectedValue = "Zm17Ig";
        String prob = Utils.base64timestamp(expectedValue.getBytes());
        String realValue = Utils.encodeBase64TimestampFromDate(prob);
        assertArrayEquals(expectedValue.toCharArray(),realValue.toCharArray());

    }
    @Test
    void Base62EncodedTimestampTest() {
        try {
            String expectedValue = "1rBDnz";
            String prob = Utils.base62timestamp(expectedValue.getBytes());
            String realValue = Utils.encodeBase62TimestampFromDate(prob);
            assertArrayEquals(expectedValue.toCharArray(), realValue.toCharArray());
        }catch (Exception e) {
            fail(e.getMessage());
        }
    }
}
