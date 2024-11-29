package one.d4d.signsaboteur.itsdangerous.crypto;

import com.google.common.primitives.Bytes;
import one.d4d.signsaboteur.itsdangerous.*;
import one.d4d.signsaboteur.keys.SecretKey;
import one.d4d.signsaboteur.utils.Utils;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RubyEncryptionTokenSigner extends TokenSigner {
    public RubyEncryptionTokenSigner(SecretKey key) {
        super(key);
        this.knownDerivations = EnumSet.of(Derivation.RUBY_ENCRYPTION);
    }

    public RubyEncryptionTokenSigner(byte[] sep) {
        this(new byte[]{}, sep);
    }

    public RubyEncryptionTokenSigner(byte[] secret_key, byte[] sep) {
        this(Algorithms.SHA256, Derivation.RUBY_ENCRYPTION, MessageDerivation.NONE, MessageDigestAlgorithm.NONE, secret_key, new byte[]{}, sep);
    }

    public RubyEncryptionTokenSigner(
            Algorithms digestMethod,
            Derivation keyDerivation,
            MessageDerivation messageDerivation,
            MessageDigestAlgorithm digest,
            byte[] secret_key,
            byte[] salt,
            byte[] sep) {
        super(digestMethod, keyDerivation, messageDerivation, digest, secret_key, salt, sep);
        this.knownDerivations = EnumSet.of(Derivation.RUBY_ENCRYPTION);
    }

    private byte[] decrypt(byte[] keyBytes, byte[] ciphertextBytes, byte[] ivBytes, byte[] tagBytes) throws Exception {
        try {
            byte[] cb = Base64.getDecoder().decode(ciphertextBytes);
            byte[] iv = Base64.getDecoder().decode(ivBytes);
            byte[] tag = Base64.getDecoder().decode(tagBytes);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tag.length * Byte.SIZE, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            cipher.update(cb);
            return cipher.doFinal(tag);

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException ignored){
            throw new Exception("Invalid");
        }
    }
    private String encrypt(byte[] keyBytes, byte[] ciphertextBytes, byte[] ivBytes) throws Exception {
        try {

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * Byte.SIZE, ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            byte[] encryptedData = cipher.doFinal(ciphertextBytes);
            byte[] ciphertext = Arrays.copyOf(encryptedData, encryptedData.length - 16);
            byte[] authTag = Arrays.copyOfRange(encryptedData, encryptedData.length - 16, encryptedData.length);

            return Stream.of(ciphertext, ivBytes, authTag)
                    .map(arr -> new String(Base64.getEncoder().encode(arr), Charset.defaultCharset()))
                    .collect(Collectors.joining("--"));


        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException ignored){
            throw new Exception("failed");
        }
    }

    public byte[] get_signature(byte[] value) {
        try {
            byte[] key = derive_key();
            byte[] ivBytes = new byte[12];
            // tag 16

            Random random = new Random();
            random.nextBytes(ivBytes);

            String encryptedData = encrypt(key, value, ivBytes);
            return encryptedData.substring(encryptedData.lastIndexOf("--") + 2).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return new byte[]{};
        }
    }

    public byte[] get_signature_unsafe(byte[] value) throws Exception {
        byte[] key = derive_key();
        byte[] ivBytes = new byte[12];
        // tag 16

        Random random = new Random();
        random.nextBytes(ivBytes);

        String encryptedData = encrypt(key, value, ivBytes);
        return encryptedData.substring(encryptedData.lastIndexOf("--") + 2).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] get_signature_bytes(byte[] value) {
        try {
            byte[] message = derive_message(value);
            byte[] key = derive_key();
            byte[] ivBytes = new byte[12];

            Random random = new Random();
            random.nextBytes(ivBytes);

            String encryptedData = encrypt(key, message, ivBytes);
            return encryptedData.substring(encryptedData.lastIndexOf("--") + 2).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return new byte[]{};
        }
    }

    public byte[] sign(byte[] value) {
        try {
            byte[] message = derive_message(value);
            byte[] key = derive_key();
            byte[] ivBytes = new byte[12];

            Random random = new Random();
            random.nextBytes(ivBytes);

            return encrypt(key, message, ivBytes).getBytes(StandardCharsets.UTF_8);
        }catch (Exception ignored) {}
        return value;
    }

    public boolean verify_signature(byte[] value, byte[] sign) {
        try {
            byte[] key = derive_key();
            int i = Collections.lastIndexOfSubList(Bytes.asList(value), Bytes.asList(sep));
            byte[] cipher = Arrays.copyOfRange(value, 0, i);
            byte[] iv = Arrays.copyOfRange(value, i + 1, value.length);

            decrypt(key, cipher, iv, sign);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean verify_signature_bytes(byte[] value, byte[] sign) {
        try {
            byte[] key = derive_key();
            int i = Collections.lastIndexOfSubList(Bytes.asList(value), Bytes.asList(sep));
            byte[] cipher = Arrays.copyOfRange(value, 0, i);
            byte[] iv = Arrays.copyOfRange(value, i + 1, value.length);

            decrypt(key, cipher, iv, sign);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public byte[] unsign(byte[] value) throws BadSignatureException {
        int i = Collections.lastIndexOfSubList(Bytes.asList(value), Bytes.asList(sep));
        byte[] message = Arrays.copyOfRange(value, 0, i);
        byte[] signature = Arrays.copyOfRange(value, i + 1, value.length);
        return fast_unsign(message, signature);
    }

    public byte[] fast_unsign(byte[] message, byte[] signature) throws BadSignatureException {
        try {
            byte[] key = derive_key();
            int i = Collections.lastIndexOfSubList(Bytes.asList(message), Bytes.asList(sep));
            byte[] cipher = Arrays.copyOfRange(message, 0, i);
            byte[] iv = Arrays.copyOfRange(message, i + 2, message.length);

            return decrypt(key, cipher, iv, signature);
        } catch (Exception e) {
            throw new BadSignatureException("Signature didn't match");
        }
    }
}
