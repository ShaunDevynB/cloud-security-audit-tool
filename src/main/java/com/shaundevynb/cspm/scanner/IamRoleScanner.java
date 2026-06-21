package com.shaundevynb.cspm.scanner;

import com.shaundevynb.cspm.config.AwsClientConfig;
import com.shaundevynb.cspm.model.SecurityViolation;
import com.shaundevynb.cspm.model.SecurityViolation.Severity;
import com.shaundevynb.cspm.model.SecurityViolation.ResourceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * CHECK: Over-Privileged IAM Roles
 *
 * IAM (Identity and Access Management) controls what AWS resources each
 * user, application, and service is allowed to access.
 *
 * The "Principle of Least Privilege" says: give each role ONLY the permissions
 * it actually needs, nothing more.
 *
 * This scanner flags roles that:
 * 1. Use the "AdministratorAccess" managed policy (full admin access)
 * 2. Have inline policies with "Action: *" and "Resource: *" (wildcard admin)
 * 3. Have "Action: *" on specific resources (partial wildcard)
 * 4. Allow PassRole without restrictions (privilege escalation risk)
 *
 * SEVERITY:
 * - Full admin (*:*) = CRITICAL
 * - Action wildcard = HIGH
 * - PassRole without conditions = MEDIUM
 */
public class IamRoleScanner {

    private static final Logger log = LoggerFactory.getLogger(IamRoleScanner.class);

    // The AWS-managed policy ARN for full administrator access
    private static final String ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess";

    private final AwsClientConfig awsConfig;
    private int violationCounter = 0;

    public IamRoleScanner(AwsClientConfig awsConfig) {
        this.awsConfig = awsConfig;
    }

    /**
     * Scans all IAM roles in the account.
     */
    public List<SecurityViolation> scan() {
        List<SecurityViolation> violations = new ArrayList<>();
        IamClient iam = awsConfig.iamClient(); // Fixed to use your configuration bean method

        log.info("Starting IAM role scan...");

        // Get all IAM roles (paginated — accounts can have hundreds of roles)
        List<Role> roles = new ArrayList<>();
        String marker = null;
        do {
            ListRolesRequest.Builder requestBuilder = ListRolesRequest.builder().maxItems(100);
            if (marker != null) requestBuilder.marker(marker);

            ListRolesResponse response = iam.listRoles(requestBuilder.build());
            roles.addAll(response.roles());
            marker = response.isTruncated() ? response.marker() : null;
        } while (marker != null);

        log.info("Found {} IAM roles to scan", roles.size());

        for (Role role : roles) {
            log.debug("Scanning IAM role: {}", role.roleName());

            // Check 1: Does this role have the AdministratorAccess managed policy attached?
            checkAttachedPolicies(iam, role, violations);

            // Check 2: Does this role have dangerous inline policies?
            checkInlinePolicies(iam, role, violations);
        }

        log.info("IAM scan complete. Found {} violations across {} roles",
                violations.size(), roles.size());
        return violations;
    }

    // -----------------------------------------------------------------------
    // Private check methods
    // -----------------------------------------------------------------------

    /**
     * Check 1: Look for the AdministratorAccess managed policy.
     */
    private void checkAttachedPolicies(IamClient iam, Role role,
                                        List<SecurityViolation> violations) {
        try {
            List<AttachedPolicy> attachedPolicies = iam.listAttachedRolePolicies(
                    ListAttachedRolePoliciesRequest.builder()
                            .roleName(role.roleName())
                            .build()
            ).attachedPolicies();

            for (AttachedPolicy policy : attachedPolicies) {
                if (ADMIN_POLICY_ARN.equals(policy.policyArn())) {
                    violations.add(new SecurityViolation(
                            "IAM-" + String.format("%03d", ++violationCounter),
                            Severity.CRITICAL,
                            ResourceType.IAM_ROLE,
                            role.arn(),
                            role.roleName(),
                            "us-east-1", // IAM is global
                            "IAM_ADMIN_POLICY_ATTACHED",
                            "IAM role '" + role.roleName() + "' has the AdministratorAccess policy attached. "
                                    + "This role has full read/write access to every AWS service and resource "
                                    + "in the account. This violates the principle of least privilege.",
                            "Replace AdministratorAccess with a custom policy that grants only the specific "
                                    + "actions this role actually needs. Use IAM Access Analyzer to find "
                                    + "what permissions are actually being used."
                    ));
                    log.warn("VIOLATION: Role '{}' has AdministratorAccess policy", role.roleName());
                }

                // Also check for any policy containing "FullAccess" in the name
                if (policy.policyName().contains("FullAccess") &&
                        !policy.policyArn().startsWith("arn:aws:iam::aws:policy/ReadOnly")) {
                    violations.add(new SecurityViolation(
                            "IAM-" + String.format("%03d", ++violationCounter),
                            Severity.HIGH,
                            ResourceType.IAM_ROLE,
                            role.arn(),
                            role.roleName(),
                            "us-east-1",
                            "IAM_FULL_ACCESS_POLICY",
                            "IAM role '" + role.roleName() + "' has a FullAccess policy attached: '"
                                    + policy.policyName() + "'. Review whether full access is necessary.",
                            "Replace with a more restrictive policy that grants only required actions."
                    ));
                }
            }
        } catch (IamException e) {
            log.warn("Could not check attached policies for role '{}': {}", role.roleName(), e.getMessage());
        }
    }

    /**
     * Check 2: Look for dangerous inline policies.
     */
    private void checkInlinePolicies(IamClient iam, Role role,
                                      List<SecurityViolation> violations) {
        try {
            List<String> policyNames = iam.listRolePolicies(
                    ListRolePoliciesRequest.builder()
                            .roleName(role.roleName())
                            .build()
            ).policyNames();

            for (String policyName : policyNames) {
                // Get the actual policy document
                String policyDocument = iam.getRolePolicy(
                        GetRolePolicyRequest.builder()
                                .roleName(role.roleName())
                                .policyName(policyName)
                                .build()
                ).policyDocument();

                // Policy documents are URL-encoded JSON — decode it first
                String decodedPolicy = URLDecoder.decode(policyDocument, StandardCharsets.UTF_8);

                analyzeInlinePolicy(role, policyName, decodedPolicy, violations);
            }
        } catch (IamException e) {
            log.warn("Could not check inline policies for role '{}': {}", role.roleName(), e.getMessage());
        }
    }

    /**
     * Analyzes a decoded IAM policy document string for dangerous patterns.
     */
    private void analyzeInlinePolicy(Role role, String policyName,
                                      String policyDocument, List<SecurityViolation> violations) {

        // Pattern 1: "Action": "*" AND "Resource": "*" — full admin wildcard
        boolean hasActionWildcard = policyDocument.contains("\"Action\":\"*\"") ||
                                    policyDocument.contains("\"Action\": \"*\"") ||
                                    policyDocument.contains("\"Action\":[\"*\"]");
        boolean hasResourceWildcard = policyDocument.contains("\"Resource\":\"*\"") ||
                                      policyDocument.contains("\"Resource\": \"*\"") ||
                                      policyDocument.contains("\"Resource\":[\"*\"]");

        if (hasActionWildcard && hasResourceWildcard) {
            violations.add(new SecurityViolation(
                    "IAM-" + String.format("%03d", ++violationCounter),
                    Severity.CRITICAL,
                    ResourceType.IAM_ROLE,
                    role.arn(),
                    role.roleName(),
                    "us-east-1",
                    "IAM_WILDCARD_ADMIN_INLINE_POLICY",
                    "IAM role '" + role.roleName() + "' has inline policy '" + policyName + "' "
                            + "with Action:* and Resource:* — this is full administrator access "
                            + "via an inline policy, which is even harder to audit than AdministratorAccess.",
                    "Rewrite the inline policy to list only the specific actions needed "
                            + "(e.g. 's3:GetObject' instead of '*'). Use the least-privilege principle."
            ));
            log.warn("VIOLATION: Role '{}' has wildcard admin inline policy '{}'",
                    role.roleName(), policyName);
            return; 
        }

        // Pattern 2: Action wildcard on specific resources (still dangerous)
        if (hasActionWildcard && !hasResourceWildcard) {
            violations.add(new SecurityViolation(
                    "IAM-" + String.format("%03d", ++violationCounter),
                    Severity.HIGH,
                    ResourceType.IAM_ROLE,
                    role.arn(),
                    role.roleName(),
                    "us-east-1",
                    "IAM_ACTION_WILDCARD_POLICY",
                    "IAM role '" + role.roleName() + "' has inline policy '" + policyName + "' "
                            + "with Action:* (all actions allowed on specific resources). "
                            + "This grants more permissions than necessary.",
                    "List only the specific AWS actions this role needs instead of using wildcard *."
            ));
            log.warn("VIOLATION: Role '{}' has Action:* in inline policy '{}'",
                    role.roleName(), policyName);
        }

        // Pattern 3: iam:PassRole without conditions — privilege escalation risk
        if (policyDocument.contains("iam:PassRole") && !policyDocument.contains("Condition")) {
            violations.add(new SecurityViolation(
                    "IAM-" + String.format("%03d", ++violationCounter),
                    Severity.MEDIUM,
                    ResourceType.IAM_ROLE,
                    role.arn(),
                    role.roleName(),
                    "us-east-1",
                    "IAM_PASSROLE_WITHOUT_CONDITION",
                    "IAM role '" + role.roleName() + "' has iam:PassRole permission in policy '"
                            + policyName + "' without any conditions. This can allow privilege "
                            + "escalation if an attacker gains access to this role.",
                    "Add a Condition to iam:PassRole that restricts which roles can be passed. "
                            + "Example: add 'iam:PassedToService' condition to limit PassRole "
                            + "to only specific AWS services (e.g. lambda.amazonaws.com)."
            ));
            log.warn("VIOLATION: Role '{}' has unconditioned iam:PassRole in '{}'",
                    role.roleName(), policyName);
        }
    }
}