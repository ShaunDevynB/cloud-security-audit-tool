package com.shaundevynb.cspm.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.time.Instant;

/**
 * Represents a single security misconfiguration found during an audit scan.
 *
 * Every check in the scanner creates one of these when it finds a problem.
 * This gets serialized to JSON for logging and reporting.
 */
public class SecurityViolation {

    // -----------------------------------------------------------------------
    // Severity levels — used to prioritize remediation
    // -----------------------------------------------------------------------
    public enum Severity {
        CRITICAL,   // Immediate risk of breach (e.g. public S3 bucket with sensitive data)
        HIGH,       // Serious misconfiguration (e.g. SSH open to the world)
        MEDIUM,     // Elevated risk (e.g. over-privileged IAM role)
        LOW         // Best-practice issue (e.g. missing tags)
    }

    // -----------------------------------------------------------------------
    // Which AWS service produced this violation
    // -----------------------------------------------------------------------
    public enum ResourceType {
        S3_BUCKET,
        EC2_SECURITY_GROUP,
        IAM_ROLE,
        EBS_VOLUME,
        RDS_INSTANCE
    }

    // -----------------------------------------------------------------------
    // Fields
    // -----------------------------------------------------------------------

    private String id;                  // Unique violation ID (e.g. "SG-001")
    private Severity severity;          // How bad is this?
    private ResourceType resourceType;  // What kind of AWS resource?
    private String resourceId;          // The actual AWS resource ID (e.g. "sg-0abc1234")
    private String resourceName;        // Human-readable name if available
    private String awsRegion;           // Which AWS region (e.g. "us-east-1")
    private String checkName;           // Short name of the check (e.g. "PUBLIC_S3_BUCKET")
    private String description;         // Plain-English description of the problem
    private String remediation;         // How to fix it
    private Instant detectedAt;         // When was this found

    // -----------------------------------------------------------------------
    // Constructor — used by scanner classes to create violations
    // -----------------------------------------------------------------------
    public SecurityViolation(String id, Severity severity, ResourceType resourceType,
                              String resourceId, String resourceName, String awsRegion,
                              String checkName, String description, String remediation) {
        this.id = id;
        this.severity = severity;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.resourceName = resourceName;
        this.awsRegion = awsRegion;
        this.checkName = checkName;
        this.description = description;
        this.remediation = remediation;
        this.detectedAt = Instant.now();
    }

    // Default constructor needed for JSON deserialization
    public SecurityViolation() {}

    // -----------------------------------------------------------------------
    // Getters and Setters
    // -----------------------------------------------------------------------

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }

    public ResourceType getResourceType() { return resourceType; }
    public void setResourceType(ResourceType resourceType) { this.resourceType = resourceType; }

    public String getResourceId() { return resourceId; }
    public void setResourceId(String resourceId) { this.resourceId = resourceId; }

    public String getResourceName() { return resourceName; }
    public void setResourceName(String resourceName) { this.resourceName = resourceName; }

    public String getAwsRegion() { return awsRegion; }
    public void setAwsRegion(String awsRegion) { this.awsRegion = awsRegion; }

    public String getCheckName() { return checkName; }
    public void setCheckName(String checkName) { this.checkName = checkName; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getRemediation() { return remediation; }
    public void setRemediation(String remediation) { this.remediation = remediation; }

    @JsonFormat(shape = JsonFormat.Shape.STRING)
    public Instant getDetectedAt() { return detectedAt; }
    public void setDetectedAt(Instant detectedAt) { this.detectedAt = detectedAt; }

    // -----------------------------------------------------------------------
    // toString — used in log output
    // -----------------------------------------------------------------------
    @Override
    public String toString() {
        return String.format("[%s] %s | %s | %s (%s) | %s",
                severity,
                checkName,
                resourceType,
                resourceId,
                awsRegion,
                description
        );
    }
}