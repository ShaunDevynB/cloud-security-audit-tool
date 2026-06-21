package com.shaundevynb.cspm.scanner;

import com.shaundevynb.cspm.config.AwsClientConfig;
import com.shaundevynb.cspm.model.SecurityViolation;
import com.shaundevynb.cspm.model.SecurityViolation.Severity;
import com.shaundevynb.cspm.model.SecurityViolation.ResourceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;

import java.util.ArrayList;
import java.util.List;

/**
 * CHECK: Security Groups with Dangerous Inbound Rules
 *
 * A Security Group is AWS's virtual firewall for EC2 instances. When a
 * rule allows traffic from "0.0.0.0/0" (ALL IPv4 addresses on the internet)
 * or "::/0" (ALL IPv6 addresses), it means ANYONE can try to connect.
 *
 * This is especially dangerous for:
 * - Port 22 (SSH): lets anyone attempt to log into your servers
 * - Port 3389 (RDP): lets anyone attempt to remote-desktop into Windows servers
 * - Port 3306/5432 (MySQL/PostgreSQL): exposes your database to the internet
 *
 * SEVERITY:
 * - SSH/RDP open to internet = HIGH (very common attack surface)
 * - ALL ports open to internet = CRITICAL (completely open firewall)
 * - Database ports open to internet = HIGH
 */
public class SecurityGroupScanner {

    private static final Logger log = LoggerFactory.getLogger(SecurityGroupScanner.class);

    // Well-known dangerous ports and their service names
    private static final int PORT_SSH      = 22;
    private static final int PORT_RDP      = 3389;
    private static final int PORT_MYSQL    = 3306;
    private static final int PORT_POSTGRES = 5432;
    private static final int PORT_MONGODB  = 27017;
    private static final int PORT_REDIS    = 6379;

    // The CIDR ranges that mean "entire internet"
    private static final String ALL_IPV4 = "0.0.0.0/0";
    private static final String ALL_IPV6 = "::/0";

    private final AwsClientConfig awsConfig;
    private int violationCounter = 0;

    public SecurityGroupScanner(AwsClientConfig awsConfig) {
        this.awsConfig = awsConfig;
    }

    /**
     * Scans all security groups in the account's region.
     */
    public List<SecurityViolation> scan() {
        List<SecurityViolation> violations = new ArrayList<>();
        Ec2Client ec2 = awsConfig.ec2Client(); // Fixed to call your configuration bean method

        log.info("Starting security group scan in region {}...", awsConfig.getRegion().id());

        List<SecurityGroup> securityGroups;
        try {
            securityGroups = ec2.describeSecurityGroups().securityGroups();
            log.info("Found {} security groups to scan", securityGroups.size());
        } catch (Ec2Exception e) {
            log.error("Failed to list security groups. Error: {}", e.getMessage());
            return violations;
        }

        for (SecurityGroup sg : securityGroups) {
            log.debug("Scanning security group: {} ({})", sg.groupId(), sg.groupName());

            // Check each inbound rule in this security group
            for (IpPermission permission : sg.ipPermissions()) {
                checkInboundRule(sg, permission, violations);
            }
        }

        log.info("Security group scan complete. Found {} violations across {} groups",
                violations.size(), securityGroups.size());
        return violations;
    }

    // -----------------------------------------------------------------------
    // Private check methods
    // -----------------------------------------------------------------------

    /**
     * Checks a single inbound rule for dangerous open ports.
     */
    private void checkInboundRule(SecurityGroup sg, IpPermission permission,
                                    List<SecurityViolation> violations) {

        // Collect all the source CIDR ranges in this rule
        List<String> openCidrs = new ArrayList<>();
        for (IpRange ipRange : permission.ipRanges()) {
            if (ALL_IPV4.equals(ipRange.cidrIp())) {
                openCidrs.add(ALL_IPV4);
            }
        }
        for (Ipv6Range ipv6Range : permission.ipv6Ranges()) {
            if (ALL_IPV6.equals(ipv6Range.cidrIpv6())) {
                openCidrs.add(ALL_IPV6);
            }
        }

        // If no open CIDRs, this rule is scoped — no violation
        if (openCidrs.isEmpty()) return;

        String cidrList = String.join(", ", openCidrs);
        int fromPort = permission.fromPort() != null ? permission.fromPort() : -1;
        int toPort   = permission.toPort()   != null ? permission.toPort()   : -1;
        String protocol = permission.ipProtocol();

        // Rule "-1" protocol means ALL traffic (all ports, all protocols)
        if ("-1".equals(protocol)) {
            addViolation(violations, sg, Severity.CRITICAL,
                    "SG_ALL_TRAFFIC_OPEN",
                    "Security group '" + sg.groupName() + "' (" + sg.groupId() + ") allows ALL traffic "
                            + "from the internet (" + cidrList + "). This means every port and every "
                            + "protocol is accessible from anywhere on the internet.",
                    "Remove the 'All traffic' inbound rule immediately. Only allow specific ports "
                            + "that your application actually needs, and restrict source IPs where possible."
            );
            return;
        }

        // Check individual dangerous ports
        checkPortRange(violations, sg, fromPort, toPort, cidrList,
                PORT_SSH, "SSH (port 22)", Severity.HIGH,
                "SG_SSH_OPEN_TO_INTERNET",
                "allows SSH (port 22) access from the internet (" + cidrList + "). "
                        + "This exposes your instances to brute-force and credential-stuffing attacks.",
                "Restrict port 22 to a specific IP address (your office/VPN IP). "
                        + "Better yet, use AWS Systems Manager Session Manager which doesn't require port 22 at all.");

        checkPortRange(violations, sg, fromPort, toPort, cidrList,
                PORT_RDP, "RDP (port 3389)", Severity.HIGH,
                "SG_RDP_OPEN_TO_INTERNET",
                "allows RDP (port 3389) from the internet (" + cidrList + "). "
                        + "Windows Remote Desktop exposed to the internet is a common ransomware entry point.",
                "Restrict port 3389 to a specific IP or VPN range. "
                        + "Consider using AWS Systems Manager Fleet Manager for Windows access instead.");

        checkPortRange(violations, sg, fromPort, toPort, cidrList,
                PORT_MYSQL, "MySQL (port 3306)", Severity.HIGH,
                "SG_DATABASE_OPEN_TO_INTERNET",
                "allows MySQL database access (port 3306) from the internet (" + cidrList + "). "
                        + "Databases should never be directly accessible from the internet.",
                "Remove this rule. Databases should only be accessible from your application servers. "
                        + "Place the database in a private subnet with no internet gateway route.");

        checkPortRange(violations, sg, fromPort, toPort, cidrList,
                PORT_POSTGRES, "PostgreSQL (port 5432)", Severity.HIGH,
                "SG_DATABASE_OPEN_TO_INTERNET",
                "allows PostgreSQL access (port 5432) from the internet (" + cidrList + "). "
                        + "Databases should never be directly accessible from the internet.",
                "Remove this rule. Databases should only be accessible from your application servers.");

        checkPortRange(violations, sg, fromPort, toPort, cidrList,
                PORT_MONGODB, "MongoDB (port 27017)", Severity.HIGH,
                "SG_DATABASE_OPEN_TO_INTERNET",
                "allows MongoDB access (port 27017) from the internet (" + cidrList + ").",
                "Restrict MongoDB to private subnets and remove internet access.");

        checkPortRange(violations, sg, fromPort, toPort, cidrList,
                PORT_REDIS, "Redis (port 6379)", Severity.HIGH,
                "SG_CACHE_OPEN_TO_INTERNET",
                "allows Redis access (port 6379) from the internet (" + cidrList + "). "
                        + "Redis has no built-in authentication by default.",
                "Restrict Redis to private subnets. Enable Redis AUTH if you must expose it.");
    }

    /**
     * Helper: checks if a given port falls within the permission's port range.
     */
    private void checkPortRange(List<SecurityViolation> violations, SecurityGroup sg,
                                  int fromPort, int toPort, String cidrList,
                                  int dangerousPort, String portName, Severity severity,
                                  String checkName, String descriptionSuffix, String remediation) {
        if (fromPort == -1) return;

        if (fromPort <= dangerousPort && dangerousPort <= toPort) {
            addViolation(violations, sg, severity, checkName,
                    "Security group '" + sg.groupName() + "' (" + sg.groupId() + ") " + descriptionSuffix,
                    remediation);
        }
    }

    /**
     * Helper: creates and adds a SecurityViolation to the list.
     */
    private void addViolation(List<SecurityViolation> violations, SecurityGroup sg,
                               Severity severity, String checkName,
                               String description, String remediation) {
        String sgName = sg.groupName() != null ? sg.groupName() : sg.groupId();
        violations.add(new SecurityViolation(
                "SG-" + String.format("%03d", ++violationCounter),
                severity,
                ResourceType.EC2_SECURITY_GROUP,
                sg.groupId(),
                sgName,
                awsConfig.getRegion().id(),
                checkName,
                description,
                remediation
        ));
        log.warn("VIOLATION: {}", description);
    }
}