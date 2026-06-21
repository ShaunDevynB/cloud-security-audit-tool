package com.shaundevynb.cspm.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * The final output of one complete audit scan.
 *
 * Contains all violations found, summary statistics, and metadata
 * about which AWS account was scanned and when.
 */
public class AuditReport {

    private String reportId;
    private String awsAccountId;
    private String awsRegion;
    private Instant scanStartTime;
    private Instant scanEndTime;
    private List<SecurityViolation> violations;
    private ScanSummary summary;
    private String scanStatus; // "COMPLETED", "FAILED", "PARTIAL"

    // -----------------------------------------------------------------------
    // Inner class: summary counts by severity
    // -----------------------------------------------------------------------
    public static class ScanSummary {
        private int totalViolations;
        private int critical;
        private int high;
        private int medium;
        private int low;
        private int checksRun;

        public ScanSummary(List<SecurityViolation> violations, int checksRun) {
            this.totalViolations = violations.size();
            this.checksRun = checksRun;
            this.critical = (int) violations.stream()
                    .filter(v -> v.getSeverity() == SecurityViolation.Severity.CRITICAL).count();
            this.high = (int) violations.stream()
                    .filter(v -> v.getSeverity() == SecurityViolation.Severity.HIGH).count();
            this.medium = (int) violations.stream()
                    .filter(v -> v.getSeverity() == SecurityViolation.Severity.MEDIUM).count();
            this.low = (int) violations.stream()
                    .filter(v -> v.getSeverity() == SecurityViolation.Severity.LOW).count();
        }

        public ScanSummary() {}

        public int getTotalViolations() { return totalViolations; }
        public void setTotalViolations(int totalViolations) { this.totalViolations = totalViolations; }

        public int getCritical() { return critical; }
        public void setCritical(int critical) { this.critical = critical; }

        public int getHigh() { return high; }
        public void setHigh(int high) { this.high = high; }

        public int getMedium() { return medium; }
        public void setMedium(int medium) { this.medium = medium; }

        public int getLow() { return low; }
        public void setLow(int low) { this.low = low; }

        public int getChecksRun() { return checksRun; }
        public void setChecksRun(int checksRun) { this.checksRun = checksRun; }

        @Override
        public String toString() {
            return String.format("Total: %d | CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d | Checks run: %d",
                    totalViolations, critical, high, medium, low, checksRun);
        }
    }

    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------
    public AuditReport() {
        this.violations = new ArrayList<>();
    }

    /**
     * Constructor matched exactly to the Orchestrator Service instantiation call.
     */
    public AuditReport(String reportId, String awsAccountId, String awsRegion) {
        this.reportId = reportId;
        this.awsAccountId = awsAccountId;
        this.awsRegion = awsRegion;
        this.violations = new ArrayList<>();
        this.scanStatus = "IN_PROGRESS";
    }

    public AuditReport(String reportId, String awsAccountId, String awsRegion, Instant scanStartTime) {
        this.reportId = reportId;
        this.awsAccountId = awsAccountId;
        this.awsRegion = awsRegion;
        this.scanStartTime = scanStartTime;
        this.violations = new ArrayList<>();
        this.scanStatus = "IN_PROGRESS";
    }

    // -----------------------------------------------------------------------
    // Report Finalization Methods
    // -----------------------------------------------------------------------
    
    /**
     * Matches the explicit `.finalizeReport(checksRunCounter)` signature 
     * called inside CloudSecurityAuditService.java.
     */
    public void finalizeReport(int checksRun) {
        this.summary = new ScanSummary(this.violations, checksRun);
        this.scanStatus = "COMPLETED";
    }

    public void finalize(int checksRun) {
        this.scanEndTime = Instant.now();
        this.summary = new ScanSummary(violations, checksRun);
        this.scanStatus = "COMPLETED";
    }

    public void addViolation(SecurityViolation violation) {
        this.violations.add(violation);
    }

    public void addViolations(List<SecurityViolation> newViolations) {
        this.violations.addAll(newViolations);
    }

    // -----------------------------------------------------------------------
    // Getters and Setters
    // -----------------------------------------------------------------------

    public String getReportId() { return reportId; }
    public void setReportId(String reportId) { this.reportId = reportId; }

    public String getAwsAccountId() { return awsAccountId; }
    public void setAwsAccountId(String awsAccountId) { this.awsAccountId = awsAccountId; }

    public String getAwsRegion() { return awsRegion; }
    public void setAwsRegion(String awsRegion) { this.awsRegion = awsRegion; }

    @JsonFormat(shape = JsonFormat.Shape.STRING)
    public Instant getScanStartTime() { return scanStartTime; }
    public void setScanStartTime(Instant scanStartTime) { this.scanStartTime = scanStartTime; }

    @JsonFormat(shape = JsonFormat.Shape.STRING)
    public Instant getScanEndTime() { return scanEndTime; }
    public void setScanEndTime(Instant scanEndTime) { this.scanEndTime = scanEndTime; }

    public List<SecurityViolation> getViolations() { return violations; }
    public void setViolations(List<SecurityViolation> violations) { this.violations = violations; }

    public ScanSummary getSummary() { return summary; }
    public void setSummary(ScanSummary summary) { this.summary = summary; }

    public String getScanStatus() { return scanStatus; }
    public void setScanStatus(String scanStatus) { this.scanStatus = scanStatus; }
}