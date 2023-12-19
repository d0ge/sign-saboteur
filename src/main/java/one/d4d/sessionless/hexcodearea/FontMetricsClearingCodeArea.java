package one.d4d.sessionless.hexcodearea;

import burp.api.montoya.logging.Logging;
import org.exbin.deltahex.swing.CodeArea;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;

class FontMetricsClearingCodeArea extends CodeArea {
    private final Logging logging;

    FontMetricsClearingCodeArea(Logging logging) {
        this.logging = logging;
    }

    @Override
    public void updateUI() {
        super.updateUI();

        if (logging != null) {
            // Reset fontMetrics in case Burp's font size has changed
            try {
                Field paintDataCacheField = FontMetricsClearingCodeArea.class.getSuperclass().getDeclaredField("paintDataCache");
                paintDataCacheField.setAccessible(true);

                Object paintDataCacheRef = paintDataCacheField.get(this);
                Field fontMetricsField = paintDataCacheRef.getClass().getDeclaredField("fontMetrics");
                fontMetricsField.setAccessible(true);

                fontMetricsField.set(paintDataCacheRef, null);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                StringWriter stringWriter = new StringWriter();
                PrintWriter printWriter = new PrintWriter(stringWriter);
                e.printStackTrace(printWriter);
                logging.logToError(stringWriter.toString());
            }

            // Reset colors in case Burp's theme has changed
            CodeArea codeArea = new CodeArea();
            setMainColors(codeArea.getMainColors());
            setAlternateColors(codeArea.getAlternateColors());
            setSelectionColors(codeArea.getSelectionColors());
            setMirrorSelectionColors(codeArea.getMirrorSelectionColors());
        }
    }
}
