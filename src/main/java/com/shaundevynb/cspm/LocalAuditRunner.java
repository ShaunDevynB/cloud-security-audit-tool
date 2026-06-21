package com.shaundevynb.cspm;

import com.shaundevynb.cspm.config.AwsClientConfig;
import com.shaundevynb.cspm.model.AuditReport;
import com.shaundevynb.cspm.service.CloudSecurityAuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.Region;

public class LocalAuditRunner {

    private static final Logger log = LoggerFactory.getLogger(LocalAuditRunner.class);

    public static void main(String[] args) {
        String regionStr = args.length > 0 ? args[0] : "us-east-1";
        log.info("Starting local audit - region: {}", regionStr);

        try {
            // Map raw input string to direct concrete SDK Region object context
            Region targetRegion = Region.of(regionStr.toLowerCase());
            AwsClientConfig config = new AwsClientConfig(targetRegion);
            
            CloudSecurityAuditService service = new CloudSecurityAuditService(config);
            AuditReport report = service.runFullAudit();

            System.out.println("\n========== AUDIT RESULTS ==========");
            if (report.getSummary() != null) {
                System.out.printf("Total to report: %d\n", report.getSummary().getTotalViolations());
                System.out.printf("CRITICAL : %d\n", report.getSummary().getCritical());
                System.out.printf("HIGH     : %d\n", report.getSummary().getHigh());
                System.out.printf("MEDIUM   : %d\n", report.getSummary().getMedium());
                System.out.printf("LOW      : %d\n", report.getSummary().getLow());
            }
            System.out.println("-----------------------------------");

            if (report.getViolations() != null) {
                report.getViolations().forEach(v -> {
                    System.out.println(v.toString());
                    System.out.println("-----------------------------------");
                });
            }
            System.out.println("===================================");

        } catch (Exception e) {
            log.error("Local runner execution failed", e);
        }
    }
}