package one.d4d.sessionless.utils;

import java.util.Locale;

public class HexUtils {
    private static final String VALID_HEX_PATTERN = "[0-9A-F]+";

    public static byte[] decodeHex(String hex) {
        hex = hex.toUpperCase(Locale.US);

        if (hex.length() % 2 != 0 || !hex.matches(VALID_HEX_PATTERN)) {
            throw new IllegalArgumentException("Invalid hex string: " + hex);
        }

        int nBytes = hex.length() / 2;
        byte[] bytes = new byte[nBytes];

        for (int i = 0; i < nBytes; i++) {
            bytes[i] = (byte) (hexToDecimal(hex.charAt(i * 2)) << 4 | hexToDecimal(hex.charAt(i * 2 + 1)));
        }

        return bytes;
    }

    public static String encodeHex(byte[] data) {
        StringBuilder sb = new StringBuilder();

        for (byte datum : data) {
            sb.append(decimalToHex((byte) ((datum & 0xF0) >> 4)));
            sb.append(decimalToHex((byte) (datum & 0x0F)));
        }

        return sb.toString();
    }

    private static int hexToDecimal(char hex) {
        return switch (hex) {
            case '0' -> 0;
            case '1' -> 1;
            case '2' -> 2;
            case '3' -> 3;
            case '4' -> 4;
            case '5' -> 5;
            case '6' -> 6;
            case '7' -> 7;
            case '8' -> 8;
            case '9' -> 9;
            case 'A' -> 10;
            case 'B' -> 11;
            case 'C' -> 12;
            case 'D' -> 13;
            case 'E' -> 14;
            case 'F' -> 15;
            default -> throw new IllegalArgumentException();
        };
    }

    private static char decimalToHex(byte data) {
        return switch (data) {
            case 0 -> '0';
            case 1 -> '1';
            case 2 -> '2';
            case 3 -> '3';
            case 4 -> '4';
            case 5 -> '5';
            case 6 -> '6';
            case 7 -> '7';
            case 8 -> '8';
            case 9 -> '9';
            case 10 -> 'A';
            case 11 -> 'B';
            case 12 -> 'C';
            case 13 -> 'D';
            case 14 -> 'E';
            case 15 -> 'F';
            default -> throw new IllegalArgumentException();
        };
    }
}
