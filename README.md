# REST-to-SOAP Translation Layer for Genesys Cloud

A Genesys Cloud Function designed to translate REST API requests into SOAP web service calls with enterprise-grade features including WS-Security support and retry mechanisms. This solution is particularly suited for integration scenarios requiring legacy system connectivity from Genesys Cloud.

## Key Features

- **Bi-directional Translation**
  - REST/JSON to SOAP/XML request conversion
  - SOAP/XML to REST/JSON response transformation

- **Enterprise Security**
  - WS-Security (UsernameToken with PasswordDigest)
  - HTTP Basic Authentication
  - Optional attachment size limits

- **Operational Reliability**
  - Configurable retry logic with exponential backoff
  - SOAP fault detection and handling
  - Correlation ID tracing

- **Multi-Part Support**
  - MIME attachments handling (base64 encoded)
  - SOAP 1.1/1.2 protocol compliance

- **Observability**
  - Structured logging with severity levels
  - Request/response previews
  - Error stack traces

## Prerequisites

- Genesys Cloud organization with Functions enabled
- Node.js development environment
- Target SOAP service WSDL/documentation

## Genesys Cloud Function Configuration

### Deployment Package Requirements

- Maximum ZIP file size: 256 MB
- Unencrypted ZIP format
- Package all dependencies
- Cannot be downloaded once uploaded
- More info: https://help.mypurecloud.com/articles/add-function-configuration/

### Function Settings

- **Runtime**: Node.js 18.x
- **Handler**: Path format: `{path_to_handler_module}.{export_name_of_handler_method}`
- **Timeout**: 1-15 seconds (function is terminated if exceeded)
- **Memory**: Configure based on payload size (recommended ≥512MB for attachments)

### Installation Steps

1. **Package Dependencies**
   ```bash
   npm install axios axios-retry form-data xml2js
   ```

2. **Create Deployment Package**
   ```bash
   zip -r function.zip *.js node_modules/
   ```

3. **Genesys Cloud Deployment**
   - Navigate to Admin > Functions
   - Create new Function
   - Upload `function.zip`
   - Configure handler path
   - Set appropriate timeout

## JSON Definitions

This repository includes separate JSON files for the Function configuration as Genesys Cloud Functions do not currently support import/export functionality:

- `function.json` - Core function configuration
- `input-contract.json` - Input parameter schema
- `output-contract.json` - Response schema
- `request-template.json` - Request transformation template
- `response-template.json` - Response transformation template

### Default Configuration

```json
{
  "endpoint": "https://www.dataaccess.com/webservicesserver/NumberConversion.wso",
  "requestMethod": "POST",
  "soapMethod": "NumberToWords",
  "parameters": "{\"parameters\": {\"ubiNum\": 500}}",
  "soapVersion": "1.1",
  "soapTimeout": 10000,
  "retryCount": 3
}
```

## Test SOAP Endpoint

This repository includes configuration for a test SOAP endpoint that converts numbers to words:

**Service**: NumberToWords
- **Description**: Converts a positive number into its word representation
- **Endpoint**: `https://www.dataaccess.com/webservicesserver/NumberConversion.wso`
- **Input**: Single parameter `ubiNum` (unsigned long)
- **Output**: String representation of the number

Example transformation: 
- Input: `500`
- Output: `"five hundred"`

## Usage

### Basic Invocation from Architect

```javascript
{
  "endpoint": "https://www.dataaccess.com/webservicesserver/NumberConversion.wso",
  "soapMethod": "NumberToWords",
  "parameters": "{\"parameters\": {\"ubiNum\": 42}}"
}
```

## Error Handling

| Code | Scenario | Retryable | Notes |
|------|----------|-----------|-------|
| 400 | Invalid request structure | No | Check input contract |
| 502 | SOAP fault/parsing error | Yes | Max retries configurable |
| 504 | Upstream timeout | Yes | Adjust soapTimeout |
| 5xx | Infrastructure errors | Yes | Uses exponential backoff |

## Security Considerations

1. **Credential Management**
   - Use Genesys Cloud Secret Management for credentials
   - Implement appropriate OAuth scopes

2. **Data Protection**
   - Enable SSL/TLS for all SOAP endpoints
   - Validate XML entity parsing

3. **Input Validation**
   - Use regex patterns for parameter sanitization
   - Enforce XML-safe element names

## Limitations

- **Attachment Handling**
  - Base64 encoding required for binary content
  - Streaming not supported - full content memory residency

- **XML Processing**
  - Assumes literal WSDL namespace mapping
  - No XML schema validation

- **Payload Size**
  - 256 MB maximum ZIP file size
  - 15 second maximum execution time

---
