package burp.scanner;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import one.d4d.sessionless.itsdangerous.model.SignedToken;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.Utils;

import java.util.Collections;
import java.util.List;

public class BrokenSecretKeyIssue implements AuditIssue {
    SecretKey issueSecretKey;
    HttpRequestResponse issueRequestResponse;
    AuditIssueConfidence issueConfidence;
    AuditIssueSeverity issueSeverity;


    public BrokenSecretKeyIssue(SecretKey issueSecretKey,
                                HttpRequestResponse issueRequestResponse,
                                AuditIssueConfidence issueConfidence,
                                AuditIssueSeverity issueSeverity) {
        this.issueSecretKey = issueSecretKey;
        this.issueRequestResponse = issueRequestResponse;
        this.issueConfidence = issueConfidence;
        this.issueSeverity = issueSeverity;
    }

    @Override
    public String name() {
        return Utils.getResourceString("audit_issue_name");
    }

    @Override
    public String detail() {
        return String.format(
                Utils.getResourceString("audit_issue_details"),
                this.issueSecretKey.toJSONString());
    }

    @Override
    public String remediation() {
        return Utils.getResourceString("audit_issue_remediation");
    }

    @Override
    public HttpService httpService() {
        return this.issueRequestResponse.httpService();
    }

    @Override
    public String baseUrl() {
        return this.issueRequestResponse.url();
    }

    @Override
    public AuditIssueSeverity severity() {
        return this.issueSeverity;
    }

    @Override
    public AuditIssueConfidence confidence() {
        return this.issueConfidence;
    }

    @Override
    public List<HttpRequestResponse> requestResponses() {
        return Collections.singletonList(this.issueRequestResponse);
    }

    @Override
    public List<Interaction> collaboratorInteractions() {
        return null;
    }

    @Override
    public AuditIssueDefinition definition() {
        return AuditIssueDefinition.auditIssueDefinition(
                Utils.getResourceString("audit_issue_name"),
                Utils.getResourceString("audit_issue_background"),
                Utils.getResourceString("audit_issue_remediation"),AuditIssueSeverity.HIGH);

    }
}
