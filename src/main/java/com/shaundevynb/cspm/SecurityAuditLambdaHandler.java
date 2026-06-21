package com.shaundevynb.cspm;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.shaundevynb.cspm.config.AwsClientConfig;
import com.shaundevynb.cspm.model.AuditReport;
import com.shaundevynb.cspm.model.SecurityViolation;
import com.shaundevynb.cspm.service.CloudSecurityAuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.Region;

import java.util.List;
import java.util.Map;

public class SecurityAuditLambdaHandler
        implements RequestHandler<Map<String, Object>, String> {

    private static final Logger log =
            LoggerFactory.getLogger(SecurityAuditLambdaHandler.class);

    @Override
    public String handleRequest(Map<String, Object> event, Context context) {
        log.info("Lambda invoked. Request ID: {}", context.getAwsRequestId());

        try {
            String regionStr = System.getenv("AWS_REGION");
            Region region = (regionStr != null && !regionStr.isBlank())
                    ? Region.of(regionStr)
                    : Region.US_EAST_1;

            AwsClientConfig config = new AwsClientConfig(region);
            CloudSecurityAuditService service = new CloudSecurityAuditService(config);
            AuditReport report = service.runFullAudit();

            List<SecurityViolation> violations = report.getViolations();
            int total = violations != null ? violations.size() : 0;

            String summary = String.format(
                    "Audit complete for account %s. Found %d violations.",
                    report.getAwsAccountId(),
                    total
            );

            log.info(summary);
            return summary;

        } catch (Exception e) {
            log.error("Audit failed: {}", e.getMessage(), e);
            return "AUDIT_FAILED: " + e.getMessage();
        }
    }
}