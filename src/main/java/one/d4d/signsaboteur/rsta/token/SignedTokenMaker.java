package one.d4d.signsaboteur.rsta.token;

import org.fife.ui.rsyntaxtextarea.AbstractTokenMaker;
import org.fife.ui.rsyntaxtextarea.Token;
import org.fife.ui.rsyntaxtextarea.TokenMap;
import org.fife.ui.rsyntaxtextarea.TokenTypes;

import javax.swing.text.Segment;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.function.Consumer;

import static org.fife.ui.rsyntaxtextarea.TokenTypes.NULL;

public class SignedTokenMaker extends AbstractTokenMaker {
    public static final int JWT_PART1 = TokenTypes.COMMENT_EOL;
    public static final int JWT_SEPARATOR1 = TokenTypes.COMMENT_MULTILINE;
    public static final int JWT_PART2 = TokenTypes.COMMENT_DOCUMENTATION;
    public static final int JWT_SEPARATOR2 = TokenTypes.COMMENT_KEYWORD;
    public static final int JWT_PART3 = TokenTypes.COMMENT_MARKUP;
    public static final int JWT_SEPARATOR3 = TokenTypes.RESERVED_WORD;
    public static final int JWT_PART4 = TokenTypes.RESERVED_WORD_2;
    public static final int JWT_SEPARATOR4 = TokenTypes.FUNCTION;
    public static final int JWT_PART5 = TokenTypes.LITERAL_BOOLEAN;

    public static Consumer<String> errorLogger = s -> {};

    @Override
    public TokenMap getWordsToHighlight() {
        return new TokenMap();
    }

    @Override
    public Token getTokenList(Segment text, int initialTokenType, int startOffset) {
        try {
            resetTokenList();

            char[] array = text.array;
            int offset = text.offset;
            int count = text.count;
            int end = offset + count;

            // Token starting offsets are always of the form:
            // 'startOffset + (currentTokenStart-offset)', but since startOffset and
            // offset are constant, tokens' starting positions become:
            // 'newStartOffset+currentTokenStart'.
            int newStartOffset = startOffset - offset;

            int currentTokenStart = offset;
            int currentTokenType = initialTokenType;
            int previousTokenType = initialTokenType;

            for (int i = offset; i < end; i++) {
                char c = array[i];

                currentTokenType = switch (currentTokenType) {
                    case NULL, JWT_PART1 -> c == '.' ? JWT_SEPARATOR1 : JWT_PART1;
                    case JWT_SEPARATOR1, JWT_PART2 -> c == '.' ? JWT_SEPARATOR2 : JWT_PART2;
                    case JWT_SEPARATOR2, JWT_PART3 -> c == '.' ? JWT_SEPARATOR3 : JWT_PART3;
                    case JWT_SEPARATOR3, JWT_PART4 -> c == '.' ? JWT_SEPARATOR4 : JWT_PART4;
                    case JWT_SEPARATOR4, JWT_PART5 -> JWT_PART5;
                    default -> throw new IllegalStateException("State: %d Char: %c".formatted(currentTokenType, c));
                };

                if (previousTokenType != NULL && previousTokenType != currentTokenType) {
                    addToken(text, currentTokenStart, i - 1, previousTokenType, newStartOffset + currentTokenStart);
                    currentTokenStart = i;
                }

                previousTokenType = currentTokenType;
            }

            if (currentTokenType != NULL) {
                addToken(text, currentTokenStart, end - 1, currentTokenType, newStartOffset + currentTokenStart);
            }

            addNullToken();

            return firstToken;
        } catch (Throwable t) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            t.printStackTrace(new PrintStream(outputStream));

            errorLogger.accept(outputStream.toString());

            return null;
        }
    }
}
