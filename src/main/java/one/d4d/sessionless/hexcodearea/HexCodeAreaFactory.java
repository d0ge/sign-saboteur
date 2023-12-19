package one.d4d.sessionless.hexcodearea;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import one.d4d.sessionless.utils.FontProvider;
import org.exbin.deltahex.swing.CodeArea;
import org.exbin.utils.binary_data.ByteArrayEditableData;

import static org.exbin.deltahex.ViewMode.CODE_MATRIX;

public class HexCodeAreaFactory {
    private final Logging logging;
    private final FontProvider fontProvider;

    public HexCodeAreaFactory(Logging logging, UserInterface userInterface) {
        this.logging = logging;
        this.fontProvider = new FontProvider(userInterface);
    }

    public CodeArea build() {
        CodeArea codeArea = new FontMetricsClearingCodeArea(logging);

        codeArea.setCommandHandler(new HexCodeAreaCommandHandler(codeArea));
        codeArea.setShowHeader(false);
        codeArea.setShowLineNumbers(false);
        codeArea.setViewMode(CODE_MATRIX);
        codeArea.setData(new ByteArrayEditableData());
        codeArea.setFont(fontProvider.editorFont());

        return codeArea;
    }
}
