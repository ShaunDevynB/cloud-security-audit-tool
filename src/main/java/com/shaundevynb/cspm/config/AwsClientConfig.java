package com.shaundevynb.cspm.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.sts.StsClient;

@Configuration
public class AwsClientConfig {

    private Region region = Region.US_EAST_1; // Default fallback region

    // Default constructor for Spring Boot dependency injection
    public AwsClientConfig() {
    }

    // Overloaded constructor so standalone runners can pass a custom region context
    public AwsClientConfig(Region region) {
        if (region != null) {
            this.region = region;
        }
    }

    public Region getRegion() {
        return this.region;
    }

    @Bean
    public S3Client s3Client() {
        return S3Client.builder().region(region).build();
    }

    @Bean
    public Ec2Client ec2Client() {
        return Ec2Client.builder().region(region).build();
    }

    @Bean
    public IamClient iamClient() {
        return IamClient.builder().region(region).build();
    }

    @Bean
    public StsClient stsClient() {
        return StsClient.builder().region(region).build();
    }
}