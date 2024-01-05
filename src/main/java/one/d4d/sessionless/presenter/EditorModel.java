package one.d4d.sessionless.presenter;

import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.config.SignerConfig;
import one.d4d.sessionless.itsdangerous.model.MutableSignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

class EditorModel {
    private final SignerConfig signerConfig;
    private static final String SERIALIZED_OBJECT_FORMAT_STRING = "%d - %s";

    private final List<MutableSignedToken> mutableSerializedObjects = new ArrayList<>();
    private final Object lock = new Object();

    private String message;

    public EditorModel(SignerConfig signerConfig) {
        this.signerConfig = signerConfig;
    }

    void setMessage(String content, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        synchronized (lock) {
            message = content;
            mutableSerializedObjects.clear();
            mutableSerializedObjects.addAll(SignedTokenObjectFinder.extractSignedTokenObjects(signerConfig,content,cookies,params));
        }
    }

    List<String> getSerializedObjectStrings() {
        synchronized (lock) {
            AtomicInteger counter = new AtomicInteger();

            return mutableSerializedObjects.stream()
                    .map(MutableSignedToken::getOriginal)
                    .map(serializedToken -> SERIALIZED_OBJECT_FORMAT_STRING.formatted(counter.incrementAndGet(), serializedToken))
                    .toList();
        }
    }

    String getMessage() {
        synchronized (lock) {
            // Create two lists, one containing the original, the other containing the modified version at the same index
            List<String> searchList = new ArrayList<>();
            List<String> replacementList = new ArrayList<>();

            // Add a replacement pair to the lists if the JOSEObjectPair has changed
            for (MutableSignedToken mutableSignedTokenObject : mutableSerializedObjects) {
                if (mutableSignedTokenObject.changed()) {
                    searchList.add(mutableSignedTokenObject.getOriginal());
                    replacementList.add(mutableSignedTokenObject.getModified().serialize());
                }
            }

            // Convert the lists to arrays
            String[] search = new String[searchList.size()];
            searchList.toArray(search);
            String[] replacement = new String[replacementList.size()];
            replacementList.toArray(replacement);

            // Use the Apache Commons StringUtils library to do in-place replacement
            return StringUtils.replaceEach(message, search, replacement);
        }
    }

    boolean isModified() {
        synchronized (lock) {
            return mutableSerializedObjects.stream().anyMatch(MutableSignedToken::changed);
        }
    }

    MutableSignedToken getSignedTokenObject(int index) {
        synchronized (lock) {
            return mutableSerializedObjects.get(index);
        }
    }
}
