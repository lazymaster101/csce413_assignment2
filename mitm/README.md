# MITM Attack Documentation

## Overview

This document details the Man-in-the-Middle (MITM) attack performed on the web application running on IP address `172.20.0.10` to capture and analyze unencrypted network traffic between the application and the MySQL database running on IP address `172.20.0.11`. The attack successfully revealed sensitive data transmitted in plaintext over the network.

## Setup and Environment

### Initial Environment
- **Target**: Web application with MySQL database backend
- **Database**: MySQL 8.0.45
- **Port**: 3306 (MySQL default)
- **Network**: Docker bridge network

### Prerequisites
- Docker and Docker Compose
- Wireshark
- Ubuntu VM
- Network packet capture tools (tcpdump/Wireshark)

## Steps Performed

### 1. Starting the Application

First, the Docker containers were started using Docker Compose:

```bash
docker compose up --build
```

This command builds and launches both the web application and database containers on a shared Docker bridge network.

### 2. Initial Attempt on macOS

An initial attempt was made to capture traffic directly on macOS:

```bash
# Listed Docker networks to find the bridge network ID
docker network ls

# Attempted to capture traffic on the bridge interface
sudo tcpdump -i br-<network_id> -A -s 0 'port 3306'
```

**Issue Encountered**: macOS terminal reported "no interface called br-<network_id>". This is because Docker on macOS runs in a VM, and the bridge interfaces are not directly accessible from the host system.

### 3. Solution: Ubuntu VM Setup

Following a suggestion to run the containers inside Ubuntu, the following steps were taken:

1. Installed Ubuntu VM on Windows host machine
2. Installed Docker on the Ubuntu VM
3. Ran the Docker containers within the Ubuntu environment
4. Installed Wireshark on Ubuntu for packet analysis

### 4. Packet Capture with Wireshark

#### Wireshark Configuration

1. Launched Wireshark application on Ubuntu
2. Located the Docker bridge interface (`br-<network_id>`) in the interface list
3. Double-clicked the bridge interface to start capturing
4. Applied display filter: `tcp.port == 3306`

#### Traffic Generation

To trigger database queries and generate network traffic:

1. Opened the web application in Firefox browser
2. Navigated through different pages of the application
3. Accessed various endpoints to trigger SQL queries
4. Specifically accessed `/api/secrets` endpoint

## Findings

### Captured SQL Queries

The packet capture revealed multiple unencrypted SQL queries being transmitted over the network:

#### Connection Setup
```sql
SET NAMES utf8mb4
SET AUTOCOMMIT = 0
```

#### User Data Query
```sql
SELECT id, username, email, role FROM users ORDER BY id
```

#### Secrets Query
```sql
SELECT id, secret_name, secret_value, description 
FROM secrets 
WHERE id = 1
```

### Evidence Screenshots

The following screenshots document the captured traffic:

![Screenshot 1 - Wireshark Interface](screenshot1.png)
*Caption: Wireshark showing the Docker bridge interface*

![Screenshot 2 - SQL Queries Captured](screenshot2.png)
*Caption: Unencrypted SQL queries visible in packet capture*

![Screenshot 3 - Database Responses](screenshot3.png)
*Caption: Database responses containing sensitive data*

![Screenshot 4 - Secrets Endpoint](screenshot4.png)
*Caption: Traffic from /api/secrets endpoint*

### Sensitive Data Discovered

#### Flag Captured
When accessing `/api/secrets` from the website, the following flag was visible in plaintext:

```
FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}
```

#### Password Handling Observation

While examining the captured packets, it was observed that database authentication passwords appear to be hashed with salting. Each new connection to the database shows a different password value, indicating the use of a challenge-response authentication mechanism (likely MySQL's `mysql_native_password` or `caching_sha2_password` plugin).

However, this does not protect the actual data being transmitted after authentication.

## Vulnerability Analysis

### Security Issues Identified

#### 1. Unencrypted Database Traffic

**Severity**: Critical

**Description**: All communication between the web application and MySQL database occurs over an unencrypted connection. This is explicitly confirmed in the Docker logs:

```
WARNING: SSL/TLS is DISABLED - All traffic is UNENCRYPTED!
```

**Evidence from Docker Logs**:
```
2026-02-08T19:10:43.030751Z 0 [Warning] [MY-011068] [Server] The syntax '--ssl=off' is deprecated and will be removed in a future release.
2026-02-08T19:10:46.753027Z 0 [Warning] [MY-011302] [Server] Plugin mysqlx reported: 'Failed at SSL configuration: "SSL context is not usable without certificate and private key"'
```

**Impact**:
- SQL queries are visible in plaintext
- Query results containing sensitive data are transmitted unencrypted
- User information (usernames, emails, roles) can be intercepted
- Secret data including flags and sensitive values are exposed
- Database schema and table structure can be reverse-engineered

#### 2. Deprecated Authentication Plugin

**Severity**: Medium

**Description**: The MySQL server is configured to use the deprecated `mysql_native_password` authentication plugin:

```
2026-02-08T19:10:43.030796Z 0 [Warning] [MY-010918] [Server] 'default_authentication_plugin' is deprecated and will be removed in a future release. Please use authentication_policy instead.
2026-02-08T19:10:44.105688Z 6 [Warning] [MY-013360] [Server] Plugin mysql_native_password reported: ''mysql_native_password' is deprecated and will be removed in a future release. Please use caching_sha2_password instead'
```

**Impact**:
- Using outdated authentication mechanisms
- Less secure than modern alternatives
- May be vulnerable to known attacks against older authentication schemes

#### 3. Network Exposure

**Severity**: High

**Description**: Database traffic on port 3306 is accessible from any container on the Docker bridge network.

**Impact**:
- Any compromised container on the same network can capture database traffic
- Lateral movement attacks become easier
- No network segmentation between application and database layers

### Attack Scenario

An attacker with access to the Docker bridge network (or any network path between the application and database) can:

1. Capture all database queries and responses using packet sniffing tools
2. Extract sensitive information including:
   - User credentials and personal information
   - Application secrets and configuration data
   - Business logic through SQL query analysis
   - Database schema and structure
3. Potentially modify traffic (in a more advanced MITM attack)
4. Replay captured queries
5. Use gathered information for further attacks

## Recommendations

### Immediate Actions

1. **Enable SSL/TLS for MySQL Connections**
   - Generate SSL certificates for MySQL server
   - Configure MySQL to require SSL/TLS connections
   - Update application connection strings to use SSL

2. **Update Authentication Plugin**
   - Migrate from `mysql_native_password` to `caching_sha2_password`
   - Update application database drivers if necessary

3. **Network Segmentation**
   - Implement network policies to restrict database access
   - Use Docker network isolation features
   - Consider using separate networks for different service tiers

### Long-term Security Improvements

1. **Implement End-to-End Encryption**
   - Encrypt sensitive data at the application layer
   - Use encryption at rest for database storage

2. **Network Monitoring and Intrusion Detection**
   - Deploy network monitoring tools
   - Set up alerts for unusual database traffic patterns
   - Implement intrusion detection systems (IDS)

3. **Regular Security Audits**
   - Perform periodic penetration testing
   - Conduct code reviews focusing on security
   - Keep all dependencies and systems updated

4. **Principle of Least Privilege**
   - Limit database user permissions
   - Use separate credentials for different application components
   - Implement role-based access control

## Conclusion

This MITM attack successfully demonstrated that the application transmits sensitive data over unencrypted network connections. The lack of SSL/TLS encryption for database traffic represents a critical security vulnerability that could lead to:

- Data breaches
- Unauthorized access to sensitive information
- Compliance violations (GDPR, HIPAA, PCI-DSS, etc.)
- Reputational damage

The captured flag `FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}` serves as proof of concept that network traffic can be intercepted and read by anyone with access to the network path between the application and database.

**Immediate remediation is required** to protect user data and application secrets by implementing SSL/TLS encryption for all database connections.

## Artifacts

All packet captures and screenshots are stored in this directory:

- `capture.pcap` - Full packet capture file
- `screenshot1.png` - Wireshark interface showing bridge network
- `screenshot2.png` - Captured SQL queries
- `screenshot3.png` - Database responses with sensitive data
- `screenshot4.png` - Traffic from /api/secrets endpoint

---

**Document Version**: 1.0  
**Date**: February 8, 2026  
**Attack Performed By**: Security Assessment Team