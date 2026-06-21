package com.shaundevynb.cspm;

import com.shaundevynb.cspm.config.AwsClientConfig;
import com.shaundevynb.cspm.model.AuditReport;
import com.shaundevynb.cspm.model.SecurityViolation;
import com.shaundevynb.cspm.service.CloudSecurityAuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import software.amazon.awssdk.regions.Region;

import java.util.List;

@SpringBootApplication
public class CloudSecurityAuditToolApplication {

    private static final Logger log = LoggerFactory.getLogger(CloudSecurityAuditToolApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(CloudSecurityAuditToolApplication.class, args);
    }

    /**
     * Fallback execution bean for Spring Boot application context startup.
     */
    @Bean
    public CommandLineRunner runAuditTool() {
        return args -> {
            log.info("Initializing active AWS client session via Spring Boot...");

            // Instantiate a fresh config for the main application context runner (Defaulting to us-east-1)
            AwsClientConfig awsConfig = new AwsClientConfig(Region.US_EAST_1);
            CloudSecurityAuditService auditService = new CloudSecurityAuditService(awsConfig);

            try {
                // Execute multi-domain posture evaluation
                AuditReport report = auditService.runFullAudit();

                // Output compliance visualization console log summary
                printSecurityDashboard(report);

            } catch (Exception e) {
                log.error("CRITICAL BOOT FAILURE: Security audit execution interrupted!", e);
            }
        };
    }

    /**
     * Prints a robust, clean security compliance posture dashboard to the console logs.
     */
    private void printSecurityDashboard(AuditReport report) {
        System.out.println("\n\n");
        System.out.println("=================================================================================");
        System.out.println("                      CLOUD SECURITY POSTURE REPORT (CSPM)                       ");
        System.out.println("=================================================================================");
        System.out.printf(" Report ID:    %s\n", report.getReportId());
        System.out.printf(" Target Env:   %s\n", report.getAwsAccountId());
        // FIX: Swapped report.getRegion() to report.getAwsRegion() to match model
        System.out.printf(" Region:       %s\n", report.getAwsRegion() != null ? report.getAwsRegion().toUpperCase() : "GLOBAL");
        System.out.printf(" Scan Status:  %s\n", report.getScanStatus());
        System.out.println("---------------------------------------------------------------------------------");
        System.out.println("                                EXECUTIVE SUMMARY                                ");
        System.out.println("---------------------------------------------------------------------------------");
        
        List<SecurityViolation> violations = report.getViolations();
        int totalCount = (violations != null) ? violations.size() : 0;
        System.out.printf("  [!] Total Findings Discovered: %d\n", totalCount);
        
        System.out.println("=================================================================================");
        System.out.println("                                DETAILED FINDINGS                                ");
        System.out.println("=================================================================================");

        if (violations == null || violations.isEmpty()) {
            System.out.println("  ✔ Green Account Status: No security misconfigurations or compliance gaps found!");
        } else {
            violations.forEach(v -> {
                System.out.println(v.toString());
                System.out.println("---------------------------------------------------------------------------------");
            });
        }
        System.out.println("============================ END OF COMPLIANCE AUDIT ============================\n\n");
    }
}