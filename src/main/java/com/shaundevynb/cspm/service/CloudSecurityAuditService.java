package com.shaundevynb.cspm.service;

import com.shaundevynb.cspm.config.AwsClientConfig;
import com.shaundevynb.cspm.model.AuditReport;
import com.shaundevynb.cspm.model.SecurityViolation;
import com.shaundevynb.cspm.scanner.IamRoleScanner;
import com.shaundevynb.cspm.scanner.S3BucketScanner;
import com.shaundevynb.cspm.scanner.SecurityGroupScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * ORCHESTRATOR SERVICE
 * * This service coordinates the entire cloud security assessment execution.
 * It initializes the individual rule engines (S3, Security Groups, IAM),
 * triggers their scans, aggregates the violations, tracks performance metrics,
 * and compiles the definitive AuditReport output object.
 */
public class CloudSecurityAuditService {

    private static final Logger log = LoggerFactory.getLogger(CloudSecurityAuditService.class);

    private final AwsClientConfig awsConfig;

    public CloudSecurityAuditService(AwsClientConfig awsConfig) {
        this.awsConfig = awsConfig;
    }

    /**
     * Executes a complete, multi-domain security audit scan across the targeted account.
     * * @return A fully populated AuditReport containing discovered vulnerabilities and execution metadata.
     */
    public AuditReport runFullAudit() {
        String reportId = UUID.randomUUID().toString();
        Instant startTime = Instant.now();
        
        log.info("======================================================================");
        log.info("LAUNCHING COMPREHENSIVE CLOUD SECURITY AUDIT [Report ID: {}]", reportId);
        log.info("Target Region: {}", awsConfig.getRegion().id());
        log.info("======================================================================");

        List<SecurityViolation> totalViolations = new ArrayList<>();
        int checksRunCounter = 0;

        // -------------------------------------------------------------------
        // 1. Execute S3 Storage Assessment
        // -------------------------------------------------------------------
        try {
            log.info("[ENGINE] Initializing S3 Storage Security Scanner...");
            S3BucketScanner s3Scanner = new S3BucketScanner(awsConfig);
            List<SecurityViolation> s3Results = s3Scanner.scan();
            totalViolations.addAll(s3Results);
            checksRunCounter += 2; // Public Access Block configuration check & Public Bucket Policy check
            log.info("[ENGINE] S3 Scanner complete. Discovered {} violations.", s3Results.size());
        } catch (Exception e) {
            log.error("[ENGINE_ERROR] Critical failure running S3 Scanner engine: {}", e.getMessage(), e);
        }

        // -------------------------------------------------------------------
        // 2. Execute Network Security Group Assessment
        // -------------------------------------------------------------------
        try {
            log.info("[ENGINE] Initializing Network Security Group Firewall Scanner...");
            SecurityGroupScanner sgScanner = new SecurityGroupScanner(awsConfig);
            List<SecurityViolation> sgResults = sgScanner.scan();
            totalViolations.addAll(sgResults);
            checksRunCounter += 7; // Rules checked: All Traffic Open, SSH, RDP, MySQL, Postgres, Mongo, Redis
            log.info("[ENGINE] Security Group Scanner complete. Discovered {} violations.", sgResults.size());
        } catch (Exception e) {
            log.error("[ENGINE_ERROR] Critical failure running Security Group Scanner engine: {}", e.getMessage(), e);
        }

        // -------------------------------------------------------------------
        // 3. Execute IAM Identity Assessment (Aligned with IamRoleScanner)
        // -------------------------------------------------------------------
        try {
            log.info("[ENGINE] Initializing IAM Access and Privilege Escalation Scanner...");
            IamRoleScanner iamScanner = new IamRoleScanner(awsConfig);
            List<SecurityViolation> iamResults = iamScanner.scan();
            totalViolations.addAll(iamResults);
            checksRunCounter += 4; // Managed Admin check, Inline Wildcard check, Action Wildcard check, PassRole condition check
            log.info("[ENGINE] IAM Scanner complete. Discovered {} violations.", iamResults.size());
        } catch (Exception e) {
            log.error("[ENGINE_ERROR] Critical failure running IAM Scanner engine: {}", e.getMessage(), e);
        }

        Instant endTime = Instant.now();
        log.info("======================================================================");
        log.info("ALL SECURITY SCANS COMPLETE. BUILDING FINAL AUDIT REPORT COMPILATION...");
        log.info("======================================================================");

        // Fetch target credentials out of the active configuration context to label the report
        String targetAccount = "AWS-Environment"; 

        // Generate the finalized report wrapper object
        AuditReport report = new AuditReport(reportId, targetAccount, awsConfig.getRegion().id());
        report.setScanStartTime(startTime);
        report.setScanEndTime(endTime);
        report.setViolations(totalViolations);
        
        // This calculates metric sums and changes state to "COMPLETED"
        report.finalizeReport(checksRunCounter);

        log.info("Audit Executive Summary Compiled Successfully.");
        if (report.getSummary() != null) {
            log.info("Total Risks Detected: {} [Critical: {}, High: {}, Medium: {}, Low: {}]", 
                    report.getSummary().getTotalViolations(),
                    report.getSummary().getCritical(),
                    report.getSummary().getHigh(),
                    report.getSummary().getMedium(),
                    report.getSummary().getLow());
        }
        
        return report;
    }
}