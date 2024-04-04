package burp.scanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.config.SignerConfig;
import one.d4d.signsaboteur.itsdangerous.Attack;
import one.d4d.signsaboteur.itsdangerous.BruteForce;
import one.d4d.signsaboteur.itsdangerous.model.MutableSignedToken;
import one.d4d.signsaboteur.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.signsaboteur.keys.SecretKey;
import one.d4d.signsaboteur.presenter.PresenterStore;
import one.d4d.signsaboteur.utils.Utils;

import java.util.*;

public class ScannerHandler implements ScanCheck {
    private final ScannerPresenter presenter;
    private final SignerConfig signerConfig;

    public ScannerHandler(PresenterStore presenters, SignerConfig signerConfig) {
        this.signerConfig = signerConfig;
        this.presenter = new ScannerPresenter(presenters);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse httpRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return null;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse httpRequestResponse) {
        List<AuditIssue> auditIssueList = getRequestAuditIssues(httpRequestResponse);
        auditIssueList.addAll(getResponseAuditIssues(httpRequestResponse));
        return AuditResult.auditResult(auditIssueList);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue auditIssue, AuditIssue auditIssue1) {
        return null;
    }

    private List<AuditIssue> getRequestAuditIssues(HttpRequestResponse requestResponse) {
        ByteArray request = requestResponse.request().toByteArray();
        Map<SecretKey, List<Marker>> issues = guessing(request, null, requestResponse.request().parameters());
        List<AuditIssue> auditIssueList = new ArrayList<>();
        issues.forEach(((secretKey, markers) -> {
            BrokenSecretKeyIssue issue = new BrokenSecretKeyIssue(
                    secretKey,
                    requestResponse.withRequestMarkers(markers),
                    AuditIssueConfidence.CERTAIN,
                    AuditIssueSeverity.HIGH);
            auditIssueList.add(issue);
        }));
        return auditIssueList;
    }

    private List<AuditIssue> getResponseAuditIssues(HttpRequestResponse requestResponse) {
        ByteArray response = requestResponse.response().toByteArray();
        Map<SecretKey, List<Marker>> issues = guessing(response, requestResponse.response().cookies(), null);
        List<AuditIssue> auditIssueList = new ArrayList<>();
        issues.forEach(((secretKey, markers) -> {
            BrokenSecretKeyIssue issue = new BrokenSecretKeyIssue(
                    secretKey,
                    requestResponse.withResponseMarkers(markers),
                    AuditIssueConfidence.CERTAIN,
                    AuditIssueSeverity.HIGH);
            auditIssueList.add(issue);
        }));
        return auditIssueList;
    }


    private Map<SecretKey, List<Marker>> guessing(ByteArray content, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        List<MutableSignedToken> mutableSignedTokens = new ArrayList<>(SignedTokenObjectFinder.extractSignedTokenObjects(signerConfig, content, cookies, params));

        List<SecretKey> signingKeys = this.presenter.getSigningKeys();
        Set<String> signingSecrets = this.presenter.getSigningSecrets();
        Set<String> signingSalts = this.presenter.getSigningSalts();
        Map<SecretKey, List<Marker>> issues = new HashMap<>();

        List<MutableSignedToken> unknownTokens = mutableSignedTokens
                .stream()
                .filter(mutableSignedToken -> signingKeys.stream().noneMatch(key -> key.getID().equals(Utils.getSignedTokenIDWithHash(mutableSignedToken.getOriginal()))))
                .toList();

        for (MutableSignedToken token : unknownTokens) {
            BruteForce worker = new BruteForce(signingSecrets, signingSalts, signingKeys, Attack.FAST, token.getModified());
            SecretKey foundKey = worker.parallel();
            if (foundKey != null) {
                List<Marker> highlights = new LinkedList<>();
                int start = content.indexOf(token.getOriginal());
                if (start == -1) continue;
                Marker marker = Marker.marker(start, start + token.getOriginal().length());
                highlights.add(marker);
                issues.put(foundKey, highlights);
            }
        }
        return issues;
    }

}
