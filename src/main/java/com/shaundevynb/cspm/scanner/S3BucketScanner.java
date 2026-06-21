package com.shaundevynb.cspm.scanner;

import com.shaundevynb.cspm.config.AwsClientConfig;
import com.shaundevynb.cspm.model.SecurityViolation;
import com.shaundevynb.cspm.model.SecurityViolation.Severity;
import com.shaundevynb.cspm.model.SecurityViolation.ResourceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.util.ArrayList;
import java.util.List;

public class S3BucketScanner {

    private static final Logger log = LoggerFactory.getLogger(S3BucketScanner.class);

    private final AwsClientConfig awsConfig;
    private int violationCounter = 0;

    public S3BucketScanner(AwsClientConfig awsConfig) {
        this.awsConfig = awsConfig;
    }

    public List<SecurityViolation> scan() {
        List<SecurityViolation> violations = new ArrayList<>();
        S3Client s3 = awsConfig.s3Client();

        log.info("Starting S3 bucket scan...");

        List<Bucket> buckets;
        try {
            buckets = s3.listBuckets().buckets();
            log.info("Found {} S3 buckets to scan", buckets.size());
        } catch (S3Exception e) {
            log.error("Failed to list S3 buckets: {}", e.getMessage());
            return violations;
        }

        for (Bucket bucket : buckets) {
            String bucketName = bucket.name();
            checkPublicAccessBlock(s3, bucketName, violations);
            checkBucketAcl(s3, bucketName, violations);
        }

        log.info("S3 scan complete. Found {} violations", violations.size());
        return violations;
    }

    private void checkPublicAccessBlock(S3Client s3, String bucketName,
                                         List<SecurityViolation> violations) {
        try {
            GetPublicAccessBlockResponse response = s3.getPublicAccessBlock(
                    GetPublicAccessBlockRequest.builder().bucket(bucketName).build()
            );
            PublicAccessBlockConfiguration config = response.publicAccessBlockConfiguration();

            boolean fullyBlocked = config.blockPublicAcls()
                    && config.ignorePublicAcls()
                    && config.blockPublicPolicy()
                    && config.restrictPublicBuckets();

            if (!fullyBlocked) {
                violations.add(new SecurityViolation(
                        "S3-" + String.format("%03d", ++violationCounter),
                        Severity.CRITICAL,
                        ResourceType.S3_BUCKET,
                        bucketName,
                        bucketName,
                        awsConfig.getRegion().id(),
                        "S3_PUBLIC_ACCESS_NOT_BLOCKED",
                        "Bucket '" + bucketName + "' does not have all Block Public Access settings enabled.",
                        "Go to S3 > " + bucketName + " > Permissions > Block public access > enable all 4 settings."
                ));
                log.warn("VIOLATION: Bucket '{}' has incomplete public access blocks", bucketName);
            }

        } catch (S3Exception e) {
            // SDK v2 does not have NoSuchPublicAccessBlockConfigurationException as a class
            // We catch the base S3Exception and check the error code string instead
            if (e.awsErrorDetails() != null &&
                    "NoSuchPublicAccessBlockConfiguration".equals(e.awsErrorDetails().errorCode())) {
                violations.add(new SecurityViolation(
                        "S3-" + String.format("%03d", ++violationCounter),
                        Severity.CRITICAL,
                        ResourceType.S3_BUCKET,
                        bucketName,
                        bucketName,
                        awsConfig.getRegion().id(),
                        "S3_NO_PUBLIC_ACCESS_BLOCK",
                        "Bucket '" + bucketName + "' has no Block Public Access configuration at all.",
                        "Enable all 4 Block Public Access settings in the S3 console immediately."
                ));
                log.warn("VIOLATION: Bucket '{}' has no public access block config", bucketName);
            } else {
                log.warn("Could not check public access block for '{}': {}", bucketName, e.getMessage());
            }
        }
    }

    private void checkBucketAcl(S3Client s3, String bucketName,
                                  List<SecurityViolation> violations) {
        try {
            GetBucketAclResponse aclResponse = s3.getBucketAcl(
                    GetBucketAclRequest.builder().bucket(bucketName).build()
            );

            for (Grant grant : aclResponse.grants()) {
                Grantee grantee = grant.grantee();
                if (grantee.uri() != null && (
                        grantee.uri().contains("AllUsers") ||
                        grantee.uri().contains("AuthenticatedUsers"))) {

                    violations.add(new SecurityViolation(
                            "S3-" + String.format("%03d", ++violationCounter),
                            Severity.CRITICAL,
                            ResourceType.S3_BUCKET,
                            bucketName,
                            bucketName,
                            awsConfig.getRegion().id(),
                            "S3_PUBLIC_ACL",
                            "Bucket '" + bucketName + "' has a public ACL granting "
                                    + grant.permission() + " to " + grantee.uri(),
                            "Remove public ACL grants and enable Block Public Access instead."
                    ));
                    log.warn("VIOLATION: Bucket '{}' has public ACL", bucketName);
                }
            }
        } catch (S3Exception e) {
            log.warn("Could not check ACL for '{}': {}", bucketName, e.getMessage());
        }
    }
}