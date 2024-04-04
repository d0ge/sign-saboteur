package one.d4d.signsaboteur.forms.utils;

import org.exbin.deltahex.swing.CodeArea;
import org.exbin.utils.binary_data.BinaryData;

public class FormUtils {
    public static byte[] getCodeAreaData(CodeArea codeArea) {
        BinaryData binaryData = codeArea.getData();
        int size = (int) binaryData.getDataSize();
        byte[] data = new byte[size];
        binaryData.copyToArray(0L, data, 0, size);
        return data;
    }
}
