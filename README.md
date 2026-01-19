# VCU Management Service

A Spring Boot 3.4 service for managing Vehicle Control Unit (VCU) firmware updates, device tracking, and over-the-air (OTA) update distribution.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [System Flow](#system-flow)
- [API Endpoints](#api-endpoints)
- [Security - @VerifySignature](#security---verifysignature)
- [Hardware Integration Guide](#hardware-integration-guide)
- [Configuration](#configuration)
- [Running the Service](#running-the-service)
- [Testing](#testing)

## Overview

The VCU Management Service provides:

- **Version Management**: Create, publish, and manage firmware versions
- **Device Registry**: Track VCU devices and their current firmware versions
- **Update Tasks**: Create targeted or fleet-wide firmware update campaigns
- **Call Home API**: Device-initiated check-in endpoint for receiving update instructions
- **MQTT Integration**: Real-time update notifications to devices
- **Reporting**: Analytics on version distribution and update progress

## Architecture

```mermaid
flowchart TB
    subgraph Controllers["Controllers Layer"]
        style Controllers fill:#4A90D9,stroke:#2E5A8B,color:#FFFFFF
        DAC[DeviceApiController]
        DC[DeviceController]
        VC[VersionController]
        UTC[UpdateTaskController]
        RC[ReportController]
    end

    subgraph Services["Services Layer"]
        style Services fill:#50C878,stroke:#2E8B57,color:#FFFFFF
        CHS[CallHomeService]
        CHAS[CallHomeAsyncService]
        DS[DeviceService]
        VS[VersionService]
        UTS[UpdateTaskService]
        TDS[TaskDeviceService]
        RS[ReportService]
    end

    subgraph Repositories["Data Layer"]
        style Repositories fill:#FFB347,stroke:#CC8400,color:#000000
        DR[(DeviceRepository)]
        VR[(VersionRepository)]
        TDR[(TaskDeviceRepository)]
        UTR[(UpdateTaskRepository)]
        FR[(FileRepository)]
    end

    subgraph Security["Security Layer"]
        style Security fill:#E57373,stroke:#C62828,color:#FFFFFF
        SIG["@VerifySignature"]
        JWT[JWT Auth]
        HMAC[HMAC/RSA Verify]
    end

    subgraph External["External Services"]
        style External fill:#9575CD,stroke:#5E35B1,color:#FFFFFF
        S3[S3 Storage]
        MQTT[MQTT Broker]
        DB[(PostgreSQL)]
    end

    DAC --> CHS
    DC --> DS
    VC --> VS
    UTC --> UTS
    RC --> RS

    CHS --> CHAS
    CHS --> TDS
    UTS --> TDS

    DS --> DR
    VS --> VR
    TDS --> TDR
    UTS --> UTR
    CHS --> DR

    DR --> DB
    VR --> DB
    TDR --> DB
    UTR --> DB
    FR --> DB

    VS --> S3
    TDS --> MQTT

    SIG -.-> DAC
    JWT -.-> DC
    JWT -.-> VC
    JWT -.-> UTC
```

### Layer Overview

| Layer | Description |
|-------|-------------|
| **Controllers** | REST API endpoints for admin dashboard and device communication |
| **Services** | Business logic for device management, versioning, and updates |
| **Repositories** | JPA repositories for database operations |
| **Security** | Request signature verification and JWT authentication |
| **External** | S3 for firmware storage, MQTT for device notifications |

## System Flow

### 1. Firmware Version Lifecycle

```mermaid
flowchart LR
    START((Start)) --> DRAFT
    DRAFT([DRAFT<br/>Upload file to S3])
    DRAFT -->|Publish| PUBLISHED
    PUBLISHED([PUBLISHED<br/>Available for updates])
    PUBLISHED -->|Deprecate| DEPRECATED
    DEPRECATED([DEPRECATED<br/>No longer available])

    style DRAFT fill:#1565C0,stroke:#0D47A1,color:#FFFFFF
    style PUBLISHED fill:#2E7D32,stroke:#1B5E20,color:#FFFFFF
    style DEPRECATED fill:#757575,stroke:#424242,color:#FFFFFF
    style START fill:#424242,stroke:#212121,color:#FFFFFF
```

### 2. Device Call Home Flow

This is the primary flow for devices checking for updates:

```mermaid
sequenceDiagram
    autonumber
    participant Device as VCU Device
    participant API as Device API
    participant Security as Signature Verifier
    participant Service as CallHomeService
    participant Async as CallHomeAsyncService
    participant DB as PostgreSQL

    rect rgba(21, 101, 192, 0.3)
        Note over Device,DB: Call Home Request
        Device->>+API: POST /v1/device-api/call-home<br/>+ X-RECHAJ-SIGNATURE header
        API->>+Security: Verify HMAC/RSA Signature
        Security-->>-API: Signature Valid
    end

    rect rgba(230, 81, 0, 0.3)
        Note over API,DB: Device Lookup & Update Check
        API->>+Service: processCallHome(request)
        Service->>+DB: Find device by serialNumber
        DB-->>-Service: DeviceEntity (or null)

        alt Device Not Found
            Service->>DB: Create new device
        end

        Service->>+DB: Check pending tasks
        DB-->>-Service: TaskDevice list

        Service->>+DB: Get latest published version
        DB-->>-Service: VersionEntity
    end

    rect rgba(46, 125, 50, 0.3)
        Note over Service,DB: Response & Async Processing
        Service-->>-API: CallHomeResponse
        API-->>Device: {updateAvailable, version, downloadUrl, taskId}

        Service--)Async: updateDeviceStateAsync()
        Service--)Async: logDeviceVersionAsync()
        Async--)DB: Update device & log
    end
```

**Key Points:**
- The API response is immediate; device state updates happen asynchronously
- If a device already has the target version, pending tasks are auto-marked as UPDATED
- New devices are automatically registered during call-home

### 3. Update Task Flow

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin Dashboard
    participant API as Task API
    participant Service as UpdateTaskService
    participant Job as TaskProcessingJob
    participant MQTT as MQTT Broker
    participant Device as VCU Devices

    rect rgba(230, 81, 0, 0.3)
        Note over Admin,Device: Task Creation
        Admin->>+API: POST /v1/version-tasks
        API->>+Service: create(request)
        Service->>Service: Validate version is PUBLISHED
        Service->>Service: Find target devices
        Service->>Service: Create TaskDevice entries
        Service-->>-API: UpdateTaskResponse
        API-->>-Admin: Task Created (status: ACTIVE)
    end

    rect rgba(21, 101, 192, 0.3)
        Note over Job,Device: Scheduled Processing
        loop Every 5 minutes
            Job->>Job: Find PENDING task devices
            Job->>+MQTT: Send update commands
            Note right of MQTT: Topic: vcu/command/{serialNumber}
            MQTT->>-Device: Update notification
            Job->>Job: Mark devices as SENT
        end
    end

    rect rgba(46, 125, 50, 0.3)
        Note over Device,Service: Device Update Flow
        Device->>API: POST /call-home
        API-->>Device: {downloadUrl, taskId}
        Device->>Device: Download & Install
        Device->>API: POST /ack (taskId)
        Note over API: Status: SENT → ACK
        Device->>API: POST /update-complete
        Note over API: Status: ACK → UPDATED
    end
```

### 4. Task Device Status Flow

```mermaid
flowchart LR
    subgraph Status["Task Device Status Lifecycle"]
        PENDING([PENDING])
        SENT([SENT])
        ACK([ACK])
        UPDATED([UPDATED])
        FAILED([FAILED])
    end

    PENDING -->|"MQTT notification sent"| SENT
    SENT -->|"Device acknowledges"| ACK
    ACK -->|"Update successful"| UPDATED

    PENDING -->|"Error occurred"| FAILED
    SENT -->|"Error occurred"| FAILED
    ACK -->|"Update failed"| FAILED

    style PENDING fill:#FFA726,stroke:#E65100,color:#000000
    style SENT fill:#42A5F5,stroke:#1565C0,color:#000000
    style ACK fill:#66BB6A,stroke:#2E7D32,color:#000000
    style UPDATED fill:#2E7D32,stroke:#1B5E20,color:#FFFFFF
    style FAILED fill:#EF5350,stroke:#C62828,color:#FFFFFF
```

### 5. Complete System Overview

```mermaid
flowchart TB
    subgraph Devices["VCU Devices"]
        style Devices fill:#1565C0,stroke:#0D47A1,color:#FFFFFF
        D1[VCU-001]
        D2[VCU-002]
        D3[VCU-003]
    end

    subgraph VMS["VCU Management Service"]
        style VMS fill:#7B1FA2,stroke:#4A148C,color:#FFFFFF

        subgraph API["REST API"]
            style API fill:#9C27B0,stroke:#6A1B9A,color:#FFFFFF
            DAPI[Device API<br/>@VerifySignature]
            AAPI[Admin API<br/>@JWT]
        end

        subgraph Core["Core Services"]
            style Core fill:#9C27B0,stroke:#6A1B9A,color:#FFFFFF
            CH[Call Home]
            UM[Update Manager]
            TM[Task Manager]
        end

        subgraph Jobs["Background Jobs"]
            style Jobs fill:#9C27B0,stroke:#6A1B9A,color:#FFFFFF
            TP[Task Processor]
            VL[Version Logger]
        end
    end

    subgraph Infrastructure["Infrastructure"]
        style Infrastructure fill:#E65100,stroke:#BF360C,color:#FFFFFF
        DB[(PostgreSQL)]
        S3[(S3 Storage)]
        MQ[MQTT Broker]
    end

    subgraph Admin["Admin Dashboard"]
        style Admin fill:#2E7D32,stroke:#1B5E20,color:#FFFFFF
        WEB[Web UI]
    end

    D1 & D2 & D3 <-->|"HTTPS + Signature"| DAPI
    DAPI --> CH
    CH --> UM

    WEB -->|"HTTPS + JWT"| AAPI
    AAPI --> TM
    TM --> UM

    TP --> MQ
    MQ -->|"Update Commands"| D1 & D2 & D3

    Core --> DB
    Jobs --> DB
    UM --> S3
```

## API Endpoints

### Device API (Protected by @VerifySignature)

All device API endpoints are protected by the `@VerifySignature` annotation, which enforces request signature verification using either HMAC-SHA256 or RSA signature verification.

| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| POST | `/v1/device-api/call-home` | Device check-in for updates | `@VerifySignature` (RSA/HMAC) |
| POST | `/v1/device-api/ack` | Acknowledge update receipt | `@VerifySignature` (RSA/HMAC) |
| POST | `/v1/device-api/update-complete` | Report update completion | `@VerifySignature` (RSA/HMAC) |

**Note**: The `@VerifySignature` annotation is applied to each endpoint method in `DeviceApiController`, causing the `SignatureVerificationFilter` to intercept requests and verify the `X-RECHAJ-SIGNATURE` header before allowing the request to proceed.

### Admin API (Requires JWT Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/v1/devices` | Manage devices |
| GET/POST | `/v1/versions` | Manage firmware versions |
| GET/POST | `/v1/version-tasks` | Manage update campaigns |
| GET | `/v1/reports/*` | Analytics and reporting |

## Security - @VerifySignature

The `@VerifySignature` annotation provides request authentication for device-to-service communication using either HMAC-SHA256 or RSA signature verification.

**Implementation**: All methods in `DeviceApiController` are annotated with `@VerifySignature`. The `SignatureVerificationFilter` intercepts requests to these endpoints, extracts the `X-RECHAJ-SIGNATURE` header, and verifies it using the configured method (HMAC or RSA) before allowing the request to reach the controller.

## Hardware Integration Guide

This section provides step-by-step instructions for hardware engineers implementing device-to-service communication using RSA signature verification.

### Overview

All device API endpoints (`/v1/device-api/call-home`, `/v1/device-api/ack`, `/v1/device-api/update-complete`) are protected by the `@VerifySignature` annotation, which requires request signature verification using RSA (or HMAC if configured). You must:
1. Create a JSON payload (request body)
2. Sign the payload using your **RSA private key** (SHA256withRSA algorithm)
3. Send the request with the signature in the `X-RECHAJ-SIGNATURE` header

**Important**: 
- Your device uses the **PRIVATE KEY** to sign requests
- The server uses the corresponding **PUBLIC KEY** to verify your signatures
- Never share your private key - keep it secure on your device

### Quick Start: RSA Signing

RSA provides asymmetric cryptography - your device signs with a private key, and the server verifies with the public key.

#### Step 1: Get Your RSA Private Key

Contact your system administrator to obtain your device's RSA private key. This key is unique to your device and must be kept secure. The corresponding public key is already configured on the server.

**Key Format**: The private key should be in PEM format:
```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----
```

**Security Note**: Store this private key securely on your device (encrypted storage, secure element, or TPM if available).

#### Step 2: Create the JSON Payload

Create a compact JSON string (no extra spaces, no trailing newlines). The exact string you sign must match exactly what you send in the request body.

**Example for Call Home:**
```json
{"serialNumber":"VCU-001","deviceVersion":"1.2.0","metadata":{"location":"warehouse-1"}}
```

**Example for Acknowledge:**
```json
{"serialNumber":"VCU-001","taskId":"550e8400-e29b-41d4-a716-446655440000"}
```

**Example for Update Complete:**
```json
{"serialNumber":"VCU-001","taskId":"550e8400-e29b-41d4-a716-446655440000","newVersion":"2.0.0","success":true}
```

#### Step 3: Generate RSA Signature

**C/C++ Example (using OpenSSL):**

```c
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <string.h>
#include <base64.h>  // You'll need a base64 library

/**
 * Generate RSA signature for a payload using SHA256withRSA
 * 
 * @param payload: The JSON string to sign
 * @param private_key_pem: Private key in PEM format (null-terminated string)
 * @param signature_out: Output buffer for base64-encoded signature (must be at least 512 bytes)
 * @return: 0 on success, -1 on error
 */
int generate_rsa_signature(const char* payload, const char* private_key_pem, char* signature_out) {
    EVP_PKEY* pkey = NULL;
    EVP_MD_CTX* md_ctx = NULL;
    unsigned char* signature = NULL;
    size_t signature_len;
    int result = -1;
    
    // Load private key from PEM string
    BIO* bio = BIO_new_mem_buf(private_key_pem, -1);
    if (!bio) {
        return -1;
    }
    
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        return -1;
    }
    
    // Create signature context
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // Initialize signing with SHA256
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        goto cleanup;
    }
    
    // Update with payload
    if (EVP_DigestSignUpdate(md_ctx, payload, strlen(payload)) != 1) {
        goto cleanup;
    }
    
    // Get signature length
    if (EVP_DigestSignFinal(md_ctx, NULL, &signature_len) != 1) {
        goto cleanup;
    }
    
    // Allocate buffer for signature
    signature = (unsigned char*)OPENSSL_malloc(signature_len);
    if (!signature) {
        goto cleanup;
    }
    
    // Generate signature
    if (EVP_DigestSignFinal(md_ctx, signature, &signature_len) != 1) {
        goto cleanup;
    }
    
    // Base64 encode the signature
    base64_encode(signature, signature_len, signature_out);
    
    result = 0;
    
cleanup:
    if (signature) OPENSSL_free(signature);
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    
    return result;
}

// Usage example
void send_call_home() {
    // Load your private key (from secure storage)
    const char* private_key_pem = 
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n"
        "-----END PRIVATE KEY-----\n";
    
    const char* payload = "{\"serialNumber\":\"VCU-001\",\"deviceVersion\":\"1.2.0\"}";
    char signature[512];
    
    if (generate_rsa_signature(payload, private_key_pem, signature) == 0) {
        // Send HTTP POST request with:
        // Header: X-RECHAJ-SIGNATURE: <signature>
        // Body: <payload>
    }
}
```

**Python Example (for testing):**

```python
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64
import json

def generate_rsa_signature(payload: str, private_key_pem: str) -> str:
    """Generate RSA signature using SHA256withRSA"""
    # Load private key from PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    # Sign the payload
    signature_bytes = private_key.sign(
        payload.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Base64 encode
    return base64.b64encode(signature_bytes).decode('utf-8')

# Example: Call Home
private_key_pem = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----"""

payload = json.dumps({
    "serialNumber": "VCU-001",
    "deviceVersion": "1.2.0",
    "metadata": {"location": "warehouse-1"}
}, separators=(',', ':'))  # Compact JSON - no spaces

signature = generate_rsa_signature(payload, private_key_pem)
print(f"Signature: {signature}")
```

**cURL Example (for testing):**

```bash
PRIVATE_KEY_FILE="private_key.pem"
PAYLOAD='{"serialNumber":"VCU-001","deviceVersion":"1.2.0"}'

# Generate RSA signature
SIGNATURE=$(echo -n "$PAYLOAD" | \
    openssl dgst -sha256 -sign "$PRIVATE_KEY_FILE" | \
    base64 -w 0)

# Send request
curl -X POST "https://api.example.com/v1/device-api/call-home" \
  -H "Content-Type: application/json" \
  -H "X-RECHAJ-SIGNATURE: $SIGNATURE" \
  -d "$PAYLOAD"
```

#### Step 4: Send the Request

Send an HTTP POST request with:
- **Content-Type**: `application/json`
- **X-RECHAJ-SIGNATURE**: The base64-encoded signature
- **Body**: The exact JSON payload you signed

**Example HTTP Request:**
```
POST /v1/device-api/call-home HTTP/1.1
Host: api.example.com
Content-Type: application/json
X-RECHAJ-SIGNATURE: 3xK8mP2vQ9wR5tY7uI1oA6sD4fG8hJ2kL9mN0pQ3rS6tU=
Content-Length: 65

{"serialNumber":"VCU-001","deviceVersion":"1.2.0"}
```

### Complete Device API Examples

#### 1. Call Home Endpoint

**Purpose**: Check for available firmware updates

**Endpoint**: `POST /v1/device-api/call-home`

**Request:**
```json
{
  "serialNumber": "VCU-001",
  "deviceVersion": "1.2.0",
  "metadata": {
    "location": "warehouse-1",
    "temperature": 25.5,
    "signalStrength": -65
  }
}
```

**Response (Update Available):**
```json
{
  "success": true,
  "data": {
    "updateAvailable": true,
    "latestVersion": "2.0.0",
    "downloadUrl": "https://s3.amazonaws.com/bucket/firmware/2.0.0.bin",
    "updateType": "FORCE",
    "taskId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Response (No Update):**
```json
{
  "success": true,
  "data": {
    "updateAvailable": false
  }
}
```

**C Implementation Example:**
```c
int call_home(const char* serial_number, const char* device_version, 
               const char* private_key_pem) {
    // 1. Build JSON payload (compact format)
    char payload[512];
    snprintf(payload, sizeof(payload), 
             "{\"serialNumber\":\"%s\",\"deviceVersion\":\"%s\"}",
             serial_number, device_version);
    
    // 2. Generate RSA signature using private key
    char signature[512];
    if (generate_rsa_signature(payload, private_key_pem, signature) != 0) {
        return -1;
    }
    
    // 3. Send HTTP POST request
    // Use your HTTP client library (libcurl, etc.)
    // Headers:
    //   Content-Type: application/json
    //   X-RECHAJ-SIGNATURE: <signature>
    // Body: <payload>
    
    return 0;
}
```

#### 2. Acknowledge Endpoint

**Purpose**: Acknowledge receipt of update command

**Endpoint**: `POST /v1/device-api/ack`

**Request:**
```json
{
  "serialNumber": "VCU-001",
  "taskId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Acknowledgment received"
}
```

**C Implementation Example:**
```c
int acknowledge_task(const char* serial_number, const char* task_id, 
                    const char* private_key_pem) {
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"serialNumber\":\"%s\",\"taskId\":\"%s\"}",
             serial_number, task_id);
    
    char signature[512];
    generate_rsa_signature(payload, private_key_pem, signature);
    
    // Send HTTP POST to /v1/device-api/ack
    // with X-RECHAJ-SIGNATURE header
    
    return 0;
}
```

#### 3. Update Complete Endpoint

**Purpose**: Report update completion status

**Endpoint**: `POST /v1/device-api/update-complete`

**Request (Success):**
```json
{
  "serialNumber": "VCU-001",
  "taskId": "550e8400-e29b-41d4-a716-446655440000",
  "newVersion": "2.0.0",
  "success": true
}
```

**Request (Failure):**
```json
{
  "serialNumber": "VCU-001",
  "taskId": "550e8400-e29b-41d4-a716-446655440000",
  "newVersion": "1.2.0",
  "success": false,
  "errorMessage": "Checksum verification failed"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Update completion recorded"
}
```

**C Implementation Example:**
```c
int report_update_complete(const char* serial_number, const char* task_id,
                           const char* new_version, int success,
                           const char* error_message, const char* private_key_pem) {
    char payload[512];
    if (error_message && strlen(error_message) > 0) {
        snprintf(payload, sizeof(payload),
                 "{\"serialNumber\":\"%s\",\"taskId\":\"%s\",\"newVersion\":\"%s\",\"success\":%s,\"errorMessage\":\"%s\"}",
                 serial_number, task_id, new_version, 
                 success ? "true" : "false", error_message);
    } else {
        snprintf(payload, sizeof(payload),
                 "{\"serialNumber\":\"%s\",\"taskId\":\"%s\",\"newVersion\":\"%s\",\"success\":%s}",
                 serial_number, task_id, new_version, 
                 success ? "true" : "false");
    }
    
    char signature[512];
    generate_rsa_signature(payload, private_key_pem, signature);
    
    // Send HTTP POST to /v1/device-api/update-complete
    // with X-RECHAJ-SIGNATURE header
    
    return 0;
}
```

### Alternative: HMAC Signing

If your system uses HMAC instead of RSA, you can use a shared secret key. Contact your administrator to confirm which method is configured.

**C Example for HMAC:**

```c
#include <openssl/hmac.h>
#include <openssl/sha.h>

int generate_hmac_signature(const char* payload, const char* secret_key, char* signature_out) {
    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    unsigned int hmac_len;
    
    HMAC(EVP_sha256(), 
         secret_key, strlen(secret_key),
         (unsigned char*)payload, strlen(payload),
         hmac_result, &hmac_len);
    
    base64_encode(hmac_result, SHA256_DIGEST_LENGTH, signature_out);
    return 0;
}
```

**Note**: Check with your system administrator to determine if your system uses RSA (private key) or HMAC (shared secret). The examples above show RSA, which is the standard method.

### Critical Requirements

1. **Payload Consistency**: The exact JSON string you sign must match exactly what you send in the request body. Any difference (whitespace, key ordering, etc.) will cause verification to fail.

2. **Character Encoding**: Always use UTF-8 encoding when converting strings to bytes for signing.

3. **Base64 Encoding**: The signature must be base64-encoded before sending in the header.

4. **Header Name**: Use exactly `X-RECHAJ-SIGNATURE` (case-insensitive, but use this exact format).

5. **Content-Type**: Always set `Content-Type: application/json` header.

### Error Handling

**401 Unauthorized Response:**
```json
{
  "status": 401,
  "message": "Invalid signature"
}
```

**Common Causes:**
- Missing `X-RECHAJ-SIGNATURE` header
- Incorrect private key (wrong key or key format issue)
- Payload mismatch (signed payload doesn't match request body)
- Incorrect base64 encoding
- Wrong signature algorithm (must use SHA256withRSA)
- Private key not matching the public key configured on server

**Debugging Tips:**
1. Verify the exact payload string matches between signing and sending
2. Test signature generation with a known payload and key
3. Use the cURL examples above to test your implementation
4. Check that base64 encoding is correct
5. Ensure no extra whitespace or newlines in JSON payload

### Testing Your Implementation

**Step 1: Test with cURL**
```bash
# Use your private key file
PRIVATE_KEY_FILE="private_key.pem"
PAYLOAD='{"serialNumber":"VCU-001","deviceVersion":"1.2.0"}'

# Generate RSA signature
SIGNATURE=$(echo -n "$PAYLOAD" | \
    openssl dgst -sha256 -sign "$PRIVATE_KEY_FILE" | \
    base64 -w 0)

# Test call-home endpoint
curl -v -X POST "https://your-api-url/v1/device-api/call-home" \
  -H "Content-Type: application/json" \
  -H "X-RECHAJ-SIGNATURE: $SIGNATURE" \
  -d "$PAYLOAD"
```

**Step 2: Compare with Your Implementation**
- Use the same payload and private key
- Compare the generated signature
- If signatures match, your implementation is correct
- Verify the server has the corresponding public key configured

### Security Best Practices

1. **Private Key Storage**: Store your RSA private key securely:
   - Use encrypted storage on device
   - Consider using a secure element or TPM if available
   - Never hardcode keys in source code
   - Never transmit private keys over network
2. **Key Pair Management**: 
   - Each device should have its own unique private/public key pair
   - The public key must be registered with the server before use
   - Contact administrator to register your device's public key
3. **Key Rotation**: Implement key rotation mechanism if required by your security policy
4. **HTTPS Only**: Always use HTTPS for API communication (never HTTP)
5. **Error Logging**: Don't log private keys or signatures in error messages
6. **Secure Boot**: Ensure firmware is signed and verified before execution
7. **Key Format**: Ensure private key is in PKCS#8 format (PEM) for compatibility

### Support

For questions or issues:
1. Check this guide and the [RSA_SIGNATURE_GUIDE.md](RSA_SIGNATURE_GUIDE.md) for detailed examples
2. Contact your system administrator to:
   - Obtain your device's RSA private key
   - Register your device's public key on the server
   - Verify key pair configuration
3. Review server logs for detailed error messages (if accessible)

### Key Points Summary

- ✅ **Use RSA private key** to sign requests (SHA256withRSA algorithm)
- ✅ **Server verifies** with the corresponding public key
- ✅ **Keep private key secure** - never share or expose it
- ✅ **Payload must match exactly** between signing and sending
- ✅ **Base64 encode** the signature before sending
- ✅ **Use HTTPS** for all API communication

### How It Works

```mermaid
sequenceDiagram
    participant Client as VCU Device
    participant Filter as SignatureFilter
    participant Verifier as SignatureVerifier
    participant Controller as Controller

    Client->>+Filter: HTTP Request<br/>+ X-RECHAJ-SIGNATURE
    Filter->>Filter: Extract signature header
    Filter->>Filter: Read request body

    Filter->>+Verifier: verify(body, signature)

    alt HMAC Mode
        Verifier->>Verifier: Compute HMAC-SHA256
        Verifier->>Verifier: Compare signatures
    else RSA Mode
        Verifier->>Verifier: Verify with public key
    end

    alt Valid Signature
        Verifier-->>-Filter: true
        Filter->>+Controller: Forward request
        Controller-->>-Filter: Response
        Filter-->>Client: 200 OK + Response
    else Invalid Signature
        Verifier-->>Filter: false
        Filter-->>-Client: 401 Unauthorized
    end
```

### Integration Guide

#### Step 1: Configure the Server

Add to your `application.yml`:

```yaml
vms:
  security:
    signature:
      # Use HMAC (simpler) or RSA (more secure)
      use-hmac: true
      # For HMAC - shared secret (use environment variable in production)
      secret-key: ${VMS_SIGNATURE_SECRET_KEY:your-secret-key}
      # For RSA - base64-encoded public key
      # public-key: ${VMS_SIGNATURE_PUBLIC_KEY}
```

#### Step 2: Client Implementation (HMAC)

**Java Example:**

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SignatureGenerator {
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public static String generateSignature(String payload, String secretKey)
            throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(
            secretKey.getBytes(StandardCharsets.UTF_8),
            HMAC_ALGORITHM
        );
        mac.init(keySpec);

        byte[] signatureBytes = mac.doFinal(
            payload.getBytes(StandardCharsets.UTF_8)
        );
        return Base64.getEncoder().encodeToString(signatureBytes);
    }
}

// Usage
String jsonPayload = "{\"serialNumber\":\"VCU-001\",\"deviceVersion\":\"1.0.0\"}";
String signature = SignatureGenerator.generateSignature(jsonPayload, secretKey);

HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("https://api.example.com/v1/device-api/call-home"))
    .header("Content-Type", "application/json")
    .header("X-RECHAJ-SIGNATURE", signature)
    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
    .build();
```

**Python Example:**

```python
import hmac
import hashlib
import base64
import json
import requests

def generate_signature(payload: str, secret_key: str) -> str:
    signature = hmac.new(
        secret_key.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(signature).decode('utf-8')

# Usage
payload = json.dumps({
    "serialNumber": "VCU-001",
    "deviceVersion": "1.0.0",
    "metadata": {"location": "warehouse-1"}
}, separators=(',', ':'))  # Compact JSON

signature = generate_signature(payload, secret_key)

response = requests.post(
    "https://api.example.com/v1/device-api/call-home",
    headers={
        "Content-Type": "application/json",
        "X-RECHAJ-SIGNATURE": signature
    },
    data=payload
)
```

**cURL Example:**

```bash
#!/bin/bash
SECRET_KEY="your-secret-key"
PAYLOAD='{"serialNumber":"VCU-001","deviceVersion":"1.0.0"}'

# Generate HMAC-SHA256 signature
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET_KEY" -binary | base64)

curl -X POST "https://api.example.com/v1/device-api/call-home" \
  -H "Content-Type: application/json" \
  -H "X-RECHAJ-SIGNATURE: $SIGNATURE" \
  -d "$PAYLOAD"
```

#### Step 3: Client Implementation (RSA)

For higher security, use RSA asymmetric signatures:

**Java Example:**

```java
import java.security.*;
import java.util.Base64;

public class RsaSignatureGenerator {
    public static String generateSignature(String payload, PrivateKey privateKey)
            throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(payload.getBytes(StandardCharsets.UTF_8));

        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }
}
```

#### Important Notes

1. **Payload Format**: The signature is computed on the exact JSON string sent in the request body. Ensure consistent JSON serialization (key ordering, whitespace).

2. **Header Name**: Always use `X-RECHAJ-SIGNATURE` (case-insensitive).

3. **Error Response**: Invalid signatures return HTTP 401:
   ```json
   {
     "status": 401,
     "message": "Invalid signature"
   }
   ```

4. **Applying the Annotation**: Add `@VerifySignature` to methods or classes:
   ```java
   @PostMapping("/call-home")
   @VerifySignature
   public ResponseModel<CallHomeResponse> callHome(@RequestBody CallHomeRequest request) {
       // Only called if signature is valid
   }
   ```

### Call Home Request/Response

**Request:**
```json
{
  "serialNumber": "VCU-001",
  "deviceVersion": "1.2.0",
  "metadata": {
    "location": "warehouse-1",
    "temperature": 25.5,
    "signalStrength": -65
  }
}
```

**Response (Update Available):**
```json
{
  "success": true,
  "data": {
    "updateAvailable": true,
    "latestVersion": "2.0.0",
    "downloadUrl": "https://s3.amazonaws.com/bucket/firmware/2.0.0.bin",
    "updateType": "FORCE",
    "taskId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Response (No Update):**
```json
{
  "success": true,
  "data": {
    "updateAvailable": false
  }
}
```

## Configuration

### Application Properties

```yaml
# Server
server:
  port: 8080

# Database
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/vms
    username: ${DB_USERNAME:vms}
    password: ${DB_PASSWORD:vms}

# Security
vms:
  security:
    signature:
      use-hmac: true
      secret-key: ${VMS_SIGNATURE_SECRET_KEY}
    jwt:
      use-hmac: true
      base64-secret: ${JWT_SECRET}
      issuer: rechaj

# AWS S3
aws:
  s3:
    bucket-name: ${S3_BUCKET_NAME}
    region: ${AWS_REGION:us-east-1}

# MQTT (Optional)
vms:
  mqtt:
    enabled: ${MQTT_ENABLED:false}
    broker-url: ${MQTT_BROKER_URL:tcp://localhost:1883}
    client-id: ${MQTT_CLIENT_ID:vms-service}
    username: ${MQTT_USERNAME:}
    password: ${MQTT_PASSWORD:}

# Jobs
vms:
  job:
    task-processing:
      enabled: true
      cron: "0 */5 * * * ?"  # Every 5 minutes
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DB_USERNAME` | PostgreSQL username | Yes |
| `DB_PASSWORD` | PostgreSQL password | Yes |
| `VMS_SIGNATURE_SECRET_KEY` | HMAC secret for device API | Yes |
| `JWT_SECRET` | Base64 JWT secret for admin API | Yes |
| `S3_BUCKET_NAME` | S3 bucket for firmware files | Yes |
| `AWS_REGION` | AWS region | No (default: us-east-1) |
| `MQTT_ENABLED` | Enable MQTT notifications | No (default: false) |
| `MQTT_BROKER_URL` | MQTT broker URL | If MQTT enabled |

## Running the Service

### Prerequisites

- Java 21+
- PostgreSQL 15+
- AWS S3 bucket (or LocalStack for development)
- MQTT broker (optional)

### Local Development

```bash
# Start dependencies (PostgreSQL, LocalStack)
docker-compose up -d

# Run the application
./mvnw spring-boot:run

# Or with specific profile
./mvnw spring-boot:run -Dspring-boot.run.profiles=local
```

### Docker

```bash
# Build
./mvnw package -DskipTests
docker build -t vcu-management-service .

# Run
docker run -p 8080:8080 \
  -e DB_USERNAME=vms \
  -e DB_PASSWORD=vms \
  -e VMS_SIGNATURE_SECRET_KEY=your-secret \
  vcu-management-service
```

## Testing

```bash
# Run all tests
./mvnw test

# Run with coverage report
./mvnw test jacoco:report

# View coverage report
open target/site/jacoco/index.html
```

### Test Categories

- **Unit Tests**: Service and controller unit tests with mocked dependencies
- **Integration Tests**: Full stack tests with H2 database
- **Security Tests**: Signature verification and authentication tests

## License

Proprietary - Rechaj Technologies
