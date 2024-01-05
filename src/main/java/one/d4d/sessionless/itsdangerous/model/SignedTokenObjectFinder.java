package one.d4d.sessionless.itsdangerous.model;

import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.config.SignerConfig;
import com.google.common.base.CharMatcher;
import one.d4d.sessionless.utils.Utils;
import org.apache.commons.lang3.StringUtils;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class SignedTokenObjectFinder {
    public static final char[] SEPARATORS = {'.', ':', '#', '|'};
    public static final char[] ALL_SEPARATORS = {'.', ':', '!', '#', '$', '*', ';', '@', '|', '~'};
    private static final int[] SIGNATURES_LENGTH = {20, 28, 32, 48, 64};
    private static final String SIGNED_PARAM = ".SIG";
    // Regular expressions for JWS/JWE extraction
    private static final String BASE64_REGEX = "[A-Za-z0-9-_]";
    private static final String SEPARATOR_REGEX = "[.:!#$*;@|~]";
    private static final String SIGNER_REGEX = String.format("\\.?%s*%s+%s*%s+%s+", BASE64_REGEX, SEPARATOR_REGEX, BASE64_REGEX, SEPARATOR_REGEX, BASE64_REGEX);
    private static final Pattern SIGNER_OBJECT_PATTERN = Pattern.compile(String.format("(%s)", SIGNER_REGEX));
    private static final String UNKNOWN_SIGNED_STRING_REGEXP = String.format("(%s*%s%s{26,86})",BASE64_REGEX, SEPARATOR_REGEX, BASE64_REGEX);
    private static final Pattern UNKNOWN_SIGNED_STRING_PATTERN = Pattern.compile(UNKNOWN_SIGNED_STRING_REGEXP);

    public static boolean containsSignedTokenObjects(SignerConfig signerConfig, String text, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        List<MutableSignedToken> candidates = extractSignedTokenObjects(signerConfig, text, cookies, params);
        return candidates.size() > 0;
    }

    public static List<MutableSignedToken> extractSignedTokenObjects(SignerConfig signerConfig, String text, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        List<MutableSignedToken> signedTokensObjects = new ArrayList<>();
        Map<String,String> cookiesToHashMap = convertCookiesToHashMap(cookies);
        Map<String,String> paramsToHashMap = convertParamsToHashMap(params);
        if (signerConfig.isEnableDangerous()) {
            Set<String> tokenCandidates = findCandidateSignedTokenObjectsWithin(text);
            for (String candidate : tokenCandidates) {
                parseToken(candidate)
                        .ifPresent(value ->
                                signedTokensObjects.add(new MutableSignedToken(candidate, value)));
            }
        }
        if (signerConfig.isEnableExpress()) {
            signedTokensObjects.addAll(parseExpressSignedParams(cookiesToHashMap));
            signedTokensObjects.addAll(parseExpressSignedParams(paramsToHashMap));
        }
        if(signerConfig.isEnableOAuth()) {
            cookiesToHashMap.forEach((name,value) -> {
                parseOauthProxySignedToken(name, value).ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
            });
            paramsToHashMap.forEach((name,value) -> {
                parseOauthProxySignedToken(name, value).ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
            });
        }
        if(signerConfig.isEnableTornado()) {
            cookiesToHashMap.forEach((name,value) -> {
                parseTornadoSignedToken(name, value).ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
            });
            paramsToHashMap.forEach((name,value) -> {
                parseTornadoSignedToken(name, value).ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
            });
        }
        if(signerConfig.isEnableUnknown()) {
            Set<String> stringCandidates = findCandidateUnknownSignedStringWithin(text);
            for (String candidate : stringCandidates) {
                parseUnknownSignedString(candidate)
                        .ifPresent(value ->
                                signedTokensObjects.add(new MutableSignedToken(candidate, value)));
            }
        }

        return signedTokensObjects;
    }

    public static Set<String> findCandidateSignedTokenObjectsWithin(String text) {
        Matcher m = SIGNER_OBJECT_PATTERN.matcher(text);
        Set<String> strings = new HashSet<>();

        while (m.find()) {
            String token = m.group();
            strings.add(token);
        }

        return strings;
    }

    public static Set<String> findCandidateUnknownSignedStringWithin(String text) {
        Matcher m = UNKNOWN_SIGNED_STRING_PATTERN.matcher(text);
        Set<String> strings = new HashSet<>();

        while (m.find()) {
            String token = m.group();
            strings.add(token);
        }

        return strings;
    }
    public static Optional<SignedToken> parseToken(String candidate) {
        Optional<SignedToken> dst = parseDjangoSignedToken(candidate);
        return dst.isPresent() ? dst : parseDangerousSignedToken(candidate);
    }

    private static List<MutableSignedToken> parseParameters(List<ParsedHttpParameter> params) {
        return parseSignedTokenWithinParams(params);
    }

    private static List<MutableSignedToken> parseCookies(List<Cookie> params) {
        return parseSignedTokenWithinCookies(params);
    }

    private static Map<String,String> convertParamsToHashMap(List<ParsedHttpParameter> params) {
        if (params == null) return new HashMap<>();
        return params.stream()
                .collect(Collectors.toMap(
                        ParsedHttpParameter::name,
                        ParsedHttpParameter::value)
                );
    }
    private static Map<String,String> convertCookiesToHashMap(List<Cookie> cookies) {
        if (cookies == null) return new HashMap<>();
        return cookies.stream()
                .collect(Collectors.toMap(
                        Cookie::name,
                        Cookie::value)
                );
    }
    public static List<MutableSignedToken> parseExpressSignedParams(Map<String,String> params) {
        List<MutableSignedToken> signedTokensObjects = new ArrayList<>();
        if (params != null) {
            List<String> signatures = params
                    .keySet()
                    .stream()
                    .filter(value -> value.toUpperCase().contains(SIGNED_PARAM))
                    .toList();
            for (String signature : signatures) {
                String sigValue = params.get(signature);
                String signedParameter = signature.substring(0, signature.toUpperCase().indexOf(SIGNED_PARAM));
                if(params.get(signedParameter) == null) continue;
                String signedValue = params.get(signedParameter);
                try {
                    Base64.getUrlDecoder().decode(signedValue);
                } catch (Exception e) {
                    continue;
                }
                ExpressSignedToken t = new ExpressSignedToken(signedParameter, signedValue, sigValue);
                signedTokensObjects.add(new MutableSignedToken(signedValue, t));

            }
        }

        return signedTokensObjects;
    }
    public static List<MutableSignedToken> parseSignedTokenWithinHashMap(Map<String,String> params) {
        List<MutableSignedToken> signedTokensObjects = new ArrayList<>();
        if (params != null) {
            List<String> signatures = params.keySet().stream().filter(value -> value.toUpperCase().contains(SIGNED_PARAM))
                    .toList();
            for (String signature : signatures) {
                String sigValue = params.get(signature);
                String signedParameter = signature.substring(0, signature.toUpperCase().indexOf(SIGNED_PARAM));
                if(params.get(signedParameter) == null) continue;
                String signedValue = params.get(signedParameter);
                try {
                    Base64.getUrlDecoder().decode(signedValue);
                } catch (Exception e) {
                    continue;
                }
                ExpressSignedToken t = new ExpressSignedToken(signedParameter, signedValue, sigValue);
                signedTokensObjects.add(new MutableSignedToken(signedValue, t));

            }
            params.forEach((name,value) -> {
                Optional<SignedToken> candidate = parseOauthProxySignedToken(name, value);
                candidate = candidate.isPresent() ? candidate : parseTornadoSignedToken(name, value);
                candidate.ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
            });
        }

        return signedTokensObjects;
    }
    public static List<MutableSignedToken> parseSignedTokenWithinParams(List<ParsedHttpParameter> params) {
        List<MutableSignedToken> signedTokensObjects = new ArrayList<>();
        if (params != null) {
            List<ParsedHttpParameter> signatures = params.stream()
                    .filter(value -> value.name().toUpperCase().contains(SIGNED_PARAM))
                    .toList();
            for (ParsedHttpParameter signature : signatures) {
                String sigValue = signature.value();
                String signedParameter = signature.name().substring(0, signature.name().toUpperCase().indexOf(SIGNED_PARAM));
                Optional<ParsedHttpParameter> param = params.stream()
                        .filter(value -> value.name().startsWith(signedParameter))
                        .findFirst();
                if (param.isPresent()) {
                    try {
                        Base64.getUrlDecoder().decode(param.get().value());
                    } catch (Exception e) {
                        continue;
                    }
                    ExpressSignedToken t = new ExpressSignedToken(param.get().name(), param.get().value(), sigValue);
                    signedTokensObjects.add(new MutableSignedToken(param.get().value(), t));
                }
            }
            for (ParsedHttpParameter param : params) {
                parseOauthProxySignedToken(param.name(), param.value())
                        .ifPresent(value ->
                                signedTokensObjects.add(new MutableSignedToken(param.value(), value)));
                parseTornadoSignedToken(param.name(), param.value())
                        .ifPresent(value ->
                                signedTokensObjects.add(new MutableSignedToken(param.value(), value)));
            }
        }

        return signedTokensObjects;
    }

    public static List<MutableSignedToken> parseSignedTokenWithinCookies(List<Cookie> cookies) {
        List<MutableSignedToken> signedTokensObjects = new ArrayList<>();
        if (cookies != null) {
            List<Cookie> signatures = cookies.stream()
                    .filter(value -> value.name().toUpperCase().contains(SIGNED_PARAM))
                    .toList();
            for (Cookie signature : signatures) {
                String sigValue = signature.value();
                String sigName = signature.name().substring(0, signature.name().toUpperCase().indexOf(SIGNED_PARAM));
                Optional<Cookie> cookie = cookies.stream()
                        .filter(value -> value.name().equalsIgnoreCase(sigName))
                        .findFirst();
                if (cookie.isPresent()) {
                    try {
                        Base64.getUrlDecoder().decode(cookie.get().value());
                    } catch (Exception e) {
                        continue;
                    }
                    ExpressSignedToken t = new ExpressSignedToken(cookie.get().name(), cookie.get().value(), sigValue);
                    signedTokensObjects.add(new MutableSignedToken(cookie.get().value(), t));
                }
            }
            for (Cookie cookie : cookies) {
                parseOauthProxySignedToken(cookie.name(), cookie.value())
                        .ifPresent(value ->
                                signedTokensObjects.add(new MutableSignedToken(cookie.value(), value)));
                parseTornadoSignedToken(cookie.name(), cookie.value())
                        .ifPresent(value ->
                                signedTokensObjects.add(new MutableSignedToken(cookie.value(), value)));
            }
        }

        return signedTokensObjects;
    }


    public static Optional<SignedToken> parseOauthProxySignedToken(String key, String value) {
        char sep = '|';
        String[] parts = StringUtils.split(value, sep);
        if (parts.length == 3) {
            String payload = parts[0];
            String timestamp = parts[1];
            String signature = parts[2];
            try {
                Base64.getUrlDecoder().decode(payload);
                Base64.getUrlDecoder().decode(signature);
            } catch (Exception e) {
                return Optional.empty();
            }
            if (Utils.timestamp(timestamp.getBytes()).equals("Not a timestamp")) return Optional.empty();

            OauthProxySignedToken t = new OauthProxySignedToken(key, payload, timestamp, signature);
            return Optional.of(t);
        }

        return Optional.empty();
    }

    private static String extractFormattedField(String field) {
        String[] parts = StringUtils.split(field, ":");
        if (parts.length == 2) {
            return parts[1];
        }
        return "";
    }

    private static String unquoteCookie(String cookie) {
        return cookie.replaceAll("^\"|\"$", "");
    }
    public static Optional<SignedToken> parseTornadoSignedToken(String key, String value) {
        char sep = '|';
        String[] parts = StringUtils.split(unquoteCookie(value), sep);
        if (parts.length == 6) {
            String formatVersion = parts[0];
            String keyVersion = parts[1];
            String timestamp = extractFormattedField(parts[2]);
            String name = extractFormattedField(parts[3]);
            String payload = extractFormattedField(parts[4]);
            String signature = parts[5];
            if (!formatVersion.equals("2")) return Optional.empty();
            if (!keyVersion.equals("1:0")) return Optional.empty();
            try {
                Base64.getUrlDecoder().decode(payload);
                Utils.hexdigest2byte(signature);
            } catch (Exception e) {
                return Optional.empty();
            }
            if (Utils.timestamp(timestamp.getBytes()).equals("Not a timestamp")) return Optional.empty();

            TornadoSignedToken t = new TornadoSignedToken(
                    timestamp,
                    name,
                    payload,
                    signature
            );
            return Optional.of(t);
        }

        return Optional.empty();
    }

    private static Optional<SignedToken> parseDangerousSignedToken(String text) {
        char separator = 0;
        boolean compressed = false;
        if (text.length() < 2) return Optional.empty();
        for (char sep : SEPARATORS) {
            if (CharMatcher.is(sep).countIn(text) >= 2) {
                separator = sep;
            }
        }
        if (separator == 0) return Optional.empty();
        String payload = text;

        if (text.startsWith(".")) {
            compressed = true;
            payload = text.substring(1);
        }
        String[] parts = StringUtils.split(payload, separator);
        if (parts.length != 3) return Optional.empty();
        // Header parser
        String header = compressed ? String.format(".%s", parts[0]) : parts[0];
        try {
            Utils.base64Decompress(header.getBytes());
        } catch (Exception e) {
            return Optional.empty();
        }
        // Timestamp parser
        String timestamp = parts[1];
        if (timestamp.length() != 6) return Optional.empty();
        try {
            Utils.base64timestamp(timestamp.getBytes());
        } catch (Exception e) {
            return Optional.empty();
        }
        // Signature guesser
        String signature = parts[2];
        try {
            int length = Utils.normalization(signature.getBytes()).length;
            if(Arrays.stream(SIGNATURES_LENGTH).noneMatch(x -> x == length)) return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }

        DangerousSignedToken t = new DangerousSignedToken((byte) separator, header, timestamp, signature);
        return Optional.of(t);
    }

    public static Optional<SignedToken> parseDjangoSignedToken(String text) {
        char separator = ':';
        boolean compressed = false;
        String payload = text;

        if (text.startsWith(".")) {
            compressed = true;
            payload = text.substring(1);
        }
        String[] parts = StringUtils.split(payload, separator);
        if (parts.length != 3) return Optional.empty();
        // Header parser
        String header = compressed ? String.format(".%s", parts[0]) : parts[0];
        try {
            Utils.base64Decompress(header.getBytes());
        } catch (Exception e) {
            return Optional.empty();
        }
        // Timestamp parser
        String timestamp = parts[1];
        if (timestamp.length() != 6) return Optional.empty();
        try {
            Utils.base62timestamp(timestamp.getBytes());
        } catch (Exception e) {
            return Optional.empty();
        }
        // Signature guesser
        String signature = parts[2];
        try {
            int length = Utils.normalization(signature.getBytes()).length;
            if(Arrays.stream(SIGNATURES_LENGTH).noneMatch(x -> x == length)) return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }

        DjangoSignedToken t = new DjangoSignedToken(
                (byte) separator,
                header,
                timestamp,
                signature);
        return Optional.of(t);
    }
    public static Optional<SignedToken> parseJSONWebSignature(String text) {
        char separator = '.';
        boolean compressed = false;
        if (text.length() < 2) return Optional.empty();
        String payload = text;

        if (text.startsWith(".")) {
            compressed = true;
            payload = text.substring(1);
        }
        String[] parts = StringUtils.split(payload, separator);
        if (parts.length != 3) return Optional.empty();
        // Header parser
        String header = compressed ? String.format(".%s", parts[0]) : parts[0];
        try {
            if(!Utils.isValidJSON(Utils.base64Decompress(header.getBytes()))) return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
        // Body parser
        String body = parts[1];
        try {
            if(!Utils.isValidJSON(Utils.base64Decompress(body.getBytes()))) return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
        // Signature parser
        String signature = parts[2];
        try {
            int length = Utils.base64Decompress(signature.getBytes()).length;
            if(Arrays.stream(SIGNATURES_LENGTH).noneMatch(x -> x == length)) return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
        SignedToken t = new JSONWebSignature(header, body, signature, (byte) separator);

        return Optional.of(t);
    }

    public static Optional<SignedToken> parseUnknownSignedString(String text) {
        char separator = 0;
        for (char sep : SEPARATORS) {
            if (CharMatcher.is(sep).countIn(text) > 0) {
                separator = sep;
            }
        }
        if (separator == 0) return Optional.empty();
        int index = text.lastIndexOf(separator);
        String message = text.substring(0,index);
        String signature = text.substring(index + 1);
        try {
            int length = Utils.normalization(signature.getBytes()).length;
            if(Arrays.stream(SIGNATURES_LENGTH).noneMatch(x -> x == length)) return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }

        UnknownSignedToken t = new UnknownSignedToken(message, signature, (byte) separator);
        return Optional.of(t);
    }
}
