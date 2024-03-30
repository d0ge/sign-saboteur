package one.d4d.sessionless.itsdangerous.model;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.config.SignerConfig;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.base.CharMatcher;
import one.d4d.sessionless.itsdangerous.crypto.Signers;
import one.d4d.sessionless.utils.Utils;
import org.apache.commons.lang3.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

public class SignedTokenObjectFinder {
    public static final char[] SEPARATORS = {'.', ':', '#', '|'};
    private static final int[] SIGNATURES_LENGTH = {20, 28, 32, 48, 64};
    private static final String SIGNED_PARAM = ".SIG";
    // Regular expressions for JWS/JWE extraction

    public static boolean containsSignedTokenObjects(SignerConfig signerConfig, ByteArray text, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        List<MutableSignedToken> candidates = extractSignedTokenObjects(signerConfig, text, cookies, params);
        return !candidates.isEmpty();
    }

    public static List<MutableSignedToken> extractSignedTokenObjects(SignerConfig signerConfig, ByteArray text, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        List<MutableSignedToken> signedTokensObjects = new ArrayList<>();
        Map<String, String> cookiesToHashMap = convertCookiesToHashMap(cookies);
        Map<HttpParameterType, Map<String, String>> paramsToHashMap = convertParamsToHashMap(params);
        if (signerConfig.isEnabled(Signers.DANGEROUS)) {
            List<ByteArray> tokenCandidates = Utils.searchByteArrayBase64URLSafe(text);
            for (ByteArray candidate : tokenCandidates) {
                parseToken(candidate.toString())
                        .ifPresent(value ->
                                signedTokensObjects.add(new MutableSignedToken(candidate.toString(), value)));
            }
        }
        if (signerConfig.isEnabled(Signers.EXPRESS)) {
            signedTokensObjects.addAll(parseExpressSignedParams(cookiesToHashMap));
            paramsToHashMap.values().forEach(pairs -> signedTokensObjects.addAll(parseExpressSignedParams(pairs)));
        }
        if (signerConfig.isEnabled(Signers.OAUTH)) {
            cookiesToHashMap.forEach((name, value) -> {
                parseOauthProxySignedToken(name, value).ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
            });
            paramsToHashMap.values().forEach(pairs -> {
                pairs.forEach((name, value) -> {
                    parseOauthProxySignedToken(name, value).ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
                });
            });
        }
        if (signerConfig.isEnabled(Signers.TORNADO)) {
            cookiesToHashMap.forEach((name, value) -> {
                parseTornadoSignedToken(name, value).ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
            });
            paramsToHashMap.values().forEach(pairs -> {
                pairs.forEach((name, value) -> {
                    parseTornadoSignedToken(name, value).ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
                });
            });
        }
        if (signerConfig.isEnabled(Signers.RUBY)) {
            cookiesToHashMap.forEach((name, value) -> {
                parseRubySignedToken(name, value).ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
            });
            paramsToHashMap.values().forEach(pairs -> {
                pairs.forEach((name, value) -> {
                    parseRubySignedToken(name, value).ifPresent(v -> signedTokensObjects.add(new MutableSignedToken(value, v)));
                });
            });
        }
        if (signerConfig.isEnabled(Signers.JWT)) {
            List<ByteArray> stringCandidates  = Utils.searchByteArrayBase64URLSafe(text);
            for (ByteArray candidate : stringCandidates) {
                parseJSONWebSignature(candidate.toString())
                        .ifPresent(value ->
                                signedTokensObjects.add(new MutableSignedToken(candidate.toString(), value)));
            }
        }
        if (signerConfig.isEnabled(Signers.UNKNOWN)) {
            List<ByteArray> stringCandidates  = Utils.searchByteArrayBase64(text);
            for (ByteArray candidate : stringCandidates) {
                parseUnknownSignedString(candidate.toString())
                        .ifPresent(value ->
                                signedTokensObjects.add(new MutableSignedToken(candidate.toString(), value)));
            }
        }

        return signedTokensObjects;
    }
    private static Map<HttpParameterType, Map<String, String>> convertParamsToHashMap(List<ParsedHttpParameter> params) {
        if (params == null) return new HashMap<>();
        return params.stream().collect(Collectors.groupingBy(ParsedHttpParameter::type,
                Collectors.toMap(
                        ParsedHttpParameter::name,
                        ParsedHttpParameter::value,
                        (key1, key2) -> key1)));
    }

    private static Map<String, String> convertCookiesToHashMap(List<Cookie> cookies) {
        if (cookies == null) return new HashMap<>();
        return cookies.stream()
                .collect(Collectors.toMap(
                        Cookie::name,
                        Cookie::value,
                        (key1, key2) -> key1));
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


    public static List<MutableSignedToken> parseExpressSignedParams(Map<String, String> params) {
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
                if (params.get(signedParameter) == null) continue;
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

    public static List<MutableSignedToken> parseSignedTokenWithinHashMap(Map<String, String> params) {
        List<MutableSignedToken> signedTokensObjects = new ArrayList<>();
        if (params != null) {
            List<String> signatures = params.keySet().stream().filter(value -> value.toUpperCase().contains(SIGNED_PARAM))
                    .toList();
            for (String signature : signatures) {
                String sigValue = params.get(signature);
                String signedParameter = signature.substring(0, signature.toUpperCase().indexOf(SIGNED_PARAM));
                if (params.get(signedParameter) == null) continue;
                String signedValue = params.get(signedParameter);
                try {
                    Base64.getUrlDecoder().decode(signedValue);
                } catch (Exception e) {
                    continue;
                }
                ExpressSignedToken t = new ExpressSignedToken(signedParameter, signedValue, sigValue);
                signedTokensObjects.add(new MutableSignedToken(signedValue, t));

            }
            params.forEach((name, value) -> {
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
            } catch (Exception e) {
                return Optional.empty();
            }
            try {
                byte[] sign = Utils.normalization(signature.getBytes());
                if (sign == null) return Optional.empty();
                if (Arrays.stream(SIGNATURES_LENGTH).noneMatch(x -> x == sign.length)) return Optional.empty();
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
            byte[] sign = Utils.normalization(signature.getBytes());
            if (sign == null) return Optional.empty();
            if (Arrays.stream(SIGNATURES_LENGTH).noneMatch(x -> x == sign.length)) return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }

        DangerousSignedToken t = new DangerousSignedToken(new byte[]{(byte) separator}, header, timestamp, signature);
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
            byte[] sign = Utils.normalization(signature.getBytes());
            if (sign == null) return Optional.empty();
            if (Arrays.stream(SIGNATURES_LENGTH).noneMatch(x -> x == sign.length)) return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }

        DjangoSignedToken t = new DjangoSignedToken(
                new byte[]{(byte) separator},
                header,
                timestamp,
                signature);
        return Optional.of(t);
    }

    public static Optional<SignedToken> parseJSONWebSignature(String text) {
        DecodedJWT decodedJWT;
        try {
            decodedJWT = JWT.decode(text);
        } catch (JWTDecodeException exception) {
            return Optional.empty();
        }
        JSONWebSignature t = new JSONWebSignature(decodedJWT.getHeader(), decodedJWT.getPayload(), decodedJWT.getSignature(), new byte[]{(byte) '.'});
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
        String message = text.substring(0, index);
        if (message.isEmpty()) return Optional.empty();
        String signature = text.substring(index + 1);
        try {
            byte[] sign = Utils.normalization(signature.getBytes());
            if (sign == null) return Optional.empty();
            if (Arrays.stream(SIGNATURES_LENGTH).noneMatch(x -> x == sign.length)) return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }

        UnknownSignedToken t = new UnknownSignedToken(message, signature, new byte[]{(byte) separator});
        return Optional.of(t);
    }

    public static Optional<SignedToken> parseRubySignedToken(String key, String value) {
        String sep = "--";
        String[] parts = StringUtils.split(value, sep);
        if (parts.length == 2) {
            String payload = parts[0];
            String signature = parts[1];
            try {
                Base64.getUrlDecoder().decode(payload);
                byte[] sign = Utils.normalization(signature.getBytes());
                if (sign == null) return Optional.empty();
                if (Arrays.stream(SIGNATURES_LENGTH).noneMatch(x -> x == sign.length)) return Optional.empty();
            } catch (Exception e) {
                return Optional.empty();
            }
            RubySignedToken t = new RubySignedToken(payload, signature);
            return Optional.of(t);
        }

        return Optional.empty();
    }
}
