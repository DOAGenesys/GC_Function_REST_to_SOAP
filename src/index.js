/**
 * ****************************************************************************************
 * REST-to-SOAP Translation Layer
 *
 * This function receives a REST-style request payload, constructs and sends a SOAP
 * request (with optional attachments and WS-Security), then parses the SOAP response
 * and returns JSON to the caller. It includes robust retry behavior, supports HTTP Basic
 * Authentication, and can enforce optional size limits on attachments. For production usage,
 * sensitive data such as credentials should be managed externally (e.g., AWS Secrets Manager).
 *
 * The code:
 *  - Validates the incoming event and required fields.
 *  - Builds a SOAP envelope with optional WS-Security.
 *  - Handles optional multipart attachments.
 *  - Sends the request using Axios with configured retries and timeouts.
 *  - Parses the SOAP response, including fault detection, and returns JSON to the caller.
 *  - Logs essential activity with a correlation ID for tracing.
 *
 * dependencies (npm packages):
 *  axios
 *  axios-retry
 *  form-data
 *  xml2js
 *
 * ****************************************************************************************
 */

'use strict';

const axios = require('axios');
const axiosRetry = require('axios-retry');
const { parseStringPromise, Builder } = require('xml2js');
const url = require('url');
const crypto = require('crypto');
const FormData = require('form-data');

/**
 * Global default configuration. In production scenarios, these values might be
 * loaded from a configuration service or specified through input parameters.
 */
const DEFAULT_CONFIG = {
  soapTimeout: 10000,            // Timeout in milliseconds (10 seconds)
  maxAttachmentSizeMB: null,     // If null, no limit is enforced; set a number to limit attachment size
  defaultSoapVersion: '1.1',     // Allowed values: '1.1' or '1.2'
  verboseLogging: false,         // Set to true for detailed SOAP envelope logging
  defaultRetries: 3,             // Number of retry attempts on network/5xx errors
  exponentialBackoff: true       // Use exponential backoff for axios retry
};

/**
 * AWS Lambda Handler
 * Acts as a comprehensive REST-to-SOAP translation middleware. The function expects an event
 * object with the following minimal required fields:
 *   - endpoint: string (SOAP service endpoint URL)
 *   - requestMethod: string ('POST' required for SOAP)
 *   - soapMethod: string (SOAP operation name, e.g., 'getUser')
 *   - parameters: object (key/value pairs representing the SOAP body)
 *
 * Optional fields include attachments, headers, soapAction, soapVersion, credentials for
 * WS-Security or Basic Auth, custom timeouts, maximum attachment size, verbose logging,
 * and retry configuration.
 *
 * @param {Object} event   - Input containing SOAP request data.
 * @param {Object} context - AWS context object.
 * @param {Function} callback - Callback function for returning the response or error.
 */
exports.handler = async (event, context, callback) => {
  // Creates a correlation ID for tracing
  const correlationId = crypto.randomBytes(16).toString('hex');

  // Retrieves or falls back to default configuration values
  const soapTimeout = typeof event.soapTimeout === 'number'
    ? event.soapTimeout
    : DEFAULT_CONFIG.soapTimeout;

  const maxAttachmentSizeMB = typeof event.maxAttachmentSizeMB === 'number'
    ? event.maxAttachmentSizeMB
    : DEFAULT_CONFIG.maxAttachmentSizeMB;

  const soapVersion = event.soapVersion || DEFAULT_CONFIG.defaultSoapVersion;

  const verboseLogging = typeof event.verboseLogging === 'boolean'
    ? event.verboseLogging
    : DEFAULT_CONFIG.verboseLogging;

  const retryCount = typeof event.retryCount === 'number'
    ? event.retryCount
    : DEFAULT_CONFIG.defaultRetries;

  // Basic Auth credentials
  const BASIC_USER = event.basicAuthUser || null;
  const BASIC_PASS = event.basicAuthPass || null;

  // WS-Security credentials
  const WSSEC_USER = event.wssecUser || null;
  const WSSEC_PASS = event.wssecPass || null;

  // Logs an initial message indicating the start of execution
  console.info(JSON.stringify({
    level: 'INFO',
    correlationId,
    message: 'Lambda execution started',
    awsRequestId: context.awsRequestId,
    functionName: context.functionName,
    endpoint: event?.endpoint,
    requestMethod: event?.requestMethod,
    soapMethod: event?.soapMethod,
    hasAttachments: Array.isArray(event?.attachments) && event.attachments.length > 0,
    customHeaders: event?.headers ? Object.keys(event.headers) : []
  }));

  try {
    // 1) Validate the incoming event
    validateEvent(event, soapVersion);

    // 2) Extract primary properties
    let {
      endpoint,
      requestMethod,
      soapMethod,
      parameters,
      attachments = [],
      headers = {},
      soapAction
    } = event;

    // Parse parameters if it's a string
    if (typeof parameters === 'string') {
      try {
        parameters = JSON.parse(parameters);
      } catch (e) {
        throw createError(`\`parameters\` is not a valid JSON string: ${e.message}. Value received: ${event.parameters}`, 400);
      }
    }


    // 3) Ensure the request method is POST
    if (requestMethod.toUpperCase() !== 'POST') {
      throw createError(`Unsupported requestMethod. Only "POST" is allowed. Received: ${requestMethod}`, 400);
    }

    // 4) Determine the SOAP namespace from the endpoint
    const parsedUrl = url.parse(endpoint);
    const namespace = buildNamespace(parsedUrl);

    // 5) Construct the SOAP Envelope, including optional WS-Security
    const includeWSSecurity = (WSSEC_USER && WSSEC_PASS) ? true : false;

    console.debug(JSON.stringify({
      level: 'DEBUG',
      correlationId,
      message: 'Parsed parameters before building SOAP request',
      parameters
    }));

    // Access the inner 'parameters' object
    const soapBodyParams = parameters.parameters;

    if (!soapBodyParams || typeof soapBodyParams !== 'object') {
        throw createError("`parameters` JSON must contain a nested object under the key 'parameters'.", 400);
    }


    const xmlRequest = buildSoapRequest({
      namespace,
      soapMethod,
      parameters: soapBodyParams, // Use the inner parameters object here
      soapVersion,
      includeWSSecurity,
      wssecUser: WSSEC_USER,
      wssecPass: WSSEC_PASS
    });

    if (verboseLogging) {
      console.debug(JSON.stringify({
        level: 'DEBUG',
        correlationId,
        message: 'Constructed SOAP envelope',
        xmlRequest
      }));
    }

    // 6) Construct the request payload as multipart if there are attachments, otherwise raw XML
    let requestData;
    let requestHeaders;
    const derivedSoapAction = soapAction || buildSoapAction(soapMethod, namespace, soapVersion);

    if (attachments.length > 0) {
      // Creates a multipart MIME payload
      const formData = new FormData();

      // SOAP Part (main.xml)
      formData.append('main', xmlRequest, {
        contentType: getSoapContentType(soapVersion),
        filename: 'main.xml'
      });

      // Validates and attaches each file
      attachments.forEach((att, idx) => {
        validateAttachment(att, idx);
        if (maxAttachmentSizeMB) {
          enforceAttachmentSizeLimit(att.content, idx, maxAttachmentSizeMB);
        }
        formData.append(
          att.fieldName || `file${idx}`,
          att.content,
          {
            filename: att.filename,
            contentType: att.contentType || 'application/octet-stream'
          }
        );
      });

      requestData = formData;
      requestHeaders = formData.getHeaders();
      requestHeaders['SOAPAction'] = derivedSoapAction;
    } else {
      // No attachments: uses standard XML payload
      requestData = xmlRequest;
      requestHeaders = {
        'Content-Type': getSoapContentType(soapVersion),
        'SOAPAction': derivedSoapAction
      };
    }

    // Merges any custom headers (e.g., x-api-key, Accept, etc.)
    if (typeof headers === 'string') {
      try {
        headers = JSON.parse(headers);
      } catch (e) {
        throw createError('`headers` is not a valid JSON string.', 400);
      }
    }
    Object.assign(requestHeaders, headers);


    // 7) Configures Axios with retry logic and optional Basic Auth
    const axiosInstance = configureAxiosWithRetry({
      soapTimeout,
      retryCount,
      correlationId,
      basicUser: BASIC_USER,
      basicPass: BASIC_PASS
    });

    // 8) Sends the SOAP request
    console.debug(JSON.stringify({
      level: 'DEBUG',
      correlationId,
      message: 'Initiating SOAP request',
      endpoint,
      soapMethod,
      finalHeaders: Object.keys(requestHeaders)
    }));

    const soapResponse = await axiosInstance.post(endpoint, requestData, {
      headers: requestHeaders,
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    // 9) Parses the SOAP response, handling potential faults
    const parsedResponse = await safeParseSoapResponse(soapResponse.data, correlationId);

    // 10) Extracts the relevant result from the parsed SOAP
    const result = extractSoapResult(parsedResponse, soapMethod);

    // 11) Returns the result as JSON
    const jsonResponse = JSON.stringify({ result });

    console.info(JSON.stringify({
      level: 'INFO',
      correlationId,
      message: 'Lambda execution successful',
      resultPreview: previewResult(result)
    }));

    callback(null, jsonResponse);

  } catch (error) {
    // Enhanced error logging
    console.error(JSON.stringify({
      level: 'ERROR',
      correlationId,
      message: 'Lambda execution failed',
      errorMessage: error.message,
      stack: error.stack,
      statusCode: error.statusCode || 500
    }));

    callback(error);
  }
};

/**
 * Validates the event object structure and critical fields.
 * @param {Object} event - The incoming Lambda event.
 * @param {string} soapVersion - The specified SOAP version ('1.1' or '1.2').
 */
function validateEvent(event, soapVersion) {
  if (!event) {
    throw createError('Event object is missing.', 400);
  }

  const requiredFields = ['endpoint', 'requestMethod', 'soapMethod', 'parameters'];
  requiredFields.forEach((field) => {
    if (event[field] === undefined || event[field] === null) {
      throw createError(`Missing required field: ${field}`, 400);
    }
  });

  if (typeof event.parameters === 'string') {
      try {
          const parsedParams = JSON.parse(event.parameters);
          if (!parsedParams || typeof parsedParams.parameters !== 'object') {
              throw new Error("must contain a nested object under the key 'parameters'");
          }
      } catch (e) {
          throw createError(`\`parameters\` must be a valid JSON string containing a nested object under the key 'parameters': ${e.message}. Value received: ${event.parameters}`, 400);
      }
  } else if (typeof event.parameters !== 'object' || Array.isArray(event.parameters) || !event.parameters.parameters || typeof event.parameters.parameters !== 'object') {
    throw createError("`parameters` must be a non-array object or a JSON string representing an object, and contain a nested object under the key 'parameters'.", 400);
  }


  if (soapVersion && !['1.1', '1.2'].includes(soapVersion)) {
    throw createError('Invalid soapVersion. Must be "1.1" or "1.2".', 400);
  }

  // Basic URL check
  try {
    new URL(event.endpoint);
  } catch (err) {
    throw createError(`Invalid endpoint URL: ${event.endpoint}`, 400);
  }
}

/**
 * Validates a single attachment object for required properties.
 * @param {Object} attachment - Attachment object.
 * @param {number} index - Index of the attachment.
 */
function validateAttachment(attachment, index) {
  if (!attachment || !attachment.content) {
    throw createError(`Attachment at index ${index} is missing 'content' property`, 400);
  }
  if (!attachment.filename) {
    throw createError(`Attachment at index ${index} is missing 'filename' property`, 400);
  }
}

/**
 * Enforces a maximum attachment size limit if configured.
 * @param {Buffer|String|Stream} content - The attachment content.
 * @param {number} index - The index of the attachment.
 * @param {number} maxSizeMB - The maximum allowed size in MB.
 */
function enforceAttachmentSizeLimit(content, index, maxSizeMB) {
  if (Buffer.isBuffer(content)) {
    const sizeMB = content.length / (1024 * 1024);
    if (sizeMB > maxSizeMB) {
      throw createError(
        `Attachment at index ${index} exceeds maximum size of ${maxSizeMB} MB (got ${sizeMB.toFixed(2)} MB)`,
        400
      );
    }
  }
}

/**
 * Builds a namespace string from the parsed URL.
 * Example: "https://www.example.com/SomeService?wsdl" -> "https://www.example.com/"
 * @param {Object} parsedUrl - The parsed URL object.
 * @returns {string} - The derived namespace.
 */
function buildNamespace(parsedUrl) {
  const pathSegments = parsedUrl.pathname ? parsedUrl.pathname.split('/').filter(Boolean) : [];
  if (pathSegments.length > 0) {
    pathSegments.pop();
  }
  const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}/${pathSegments.join('/')}`;
  const finalUrl = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  return finalUrl;
}

/**
 * Constructs the SOAP request (Envelope) with optional WS-Security.
 * @param {Object} options
 * @param {string} options.namespace - The SOAP namespace.
 * @param {string} options.soapMethod - The SOAP operation name.
 * @param {Object} options.parameters - Key-value pairs for the SOAP body.
 * @param {string} options.soapVersion - SOAP version ('1.1' or '1.2').
 * @param {boolean} options.includeWSSecurity - Whether to include WS-Security headers.
 * @param {string} options.wssecUser - WS-Security username.
 * @param {string} options.wssecPass - WS-Security password.
 * @returns {string} - The constructed SOAP XML envelope.
 */
function buildSoapRequest({
  namespace,
  soapMethod,
  parameters,
  soapVersion,
  includeWSSecurity,
  wssecUser,
  wssecPass
}) {
  // Selects the SOAP Envelope namespace based on the version
  const soapEnvNs = soapVersion === '1.2'
    ? 'http://www.w3.org/2003/05/soap-envelope'
    : 'http://schemas.xmlsoap.org/soap/envelope/';

  const envelopeObj = {
    Envelope: {
      $: {
        'xmlns:soap': soapEnvNs
      },
      'soap:Header': {},
      'soap:Body': {
        [soapMethod]: {
          $: { xmlns: namespace },
          ...parameters
        }
      }
    }
  };

  // Validate parameter keys for XML compatibility
  console.debug(JSON.stringify({
    level: 'DEBUG',
    correlationId: correlationId,
    message: 'Validating parameter keys',
    parameterKeys: Object.keys(parameters)
  }));
  for (const key in parameters) {
    if (!isValidXmlName(key)) {
      throw createError(`Invalid character in parameter name: '${key}'. Parameter names must be valid XML tag names.`, 400);
    }
  }


  // Adds WS-Security headers if required
  if (includeWSSecurity) {
    envelopeObj.Envelope['soap:Header'] = buildWSSecurityHeader(wssecUser, wssecPass);
  }

  const builder = new Builder({
    xmldec: { version: '1.0', encoding: 'UTF-8' }
  });

  return builder.buildObject(envelopeObj);
}

/**
 * Checks if a string is a valid XML name.
 * @param {string} name - The name to validate.
 * @returns {boolean} - True if valid, false otherwise.
 */
function isValidXmlName(name) {
  // Basic check for characters allowed in XML names.
  // More comprehensive validation might be needed for strict XML compliance.
  return /^[a-zA-Z_][\w\-\.]*$/.test(name);
}


/**
 * Constructs the WS-Security <wsse:Security> portion with UsernameToken,
 * Nonce, Created, and PasswordDigest.
 * @param {string} wssecUser - WS-Security username.
 * @param {string} wssecPass - WS-Security password.
 * @returns {Object} - The WS-Security header object.
 */
function buildWSSecurityHeader(wssecUser, wssecPass) {
  const created = new Date().toISOString();
  const nonce = crypto.randomBytes(16);
  const nonceB64 = nonce.toString('base64');

  // The standard formula for password digest = Base64(SHA1(nonce + created + password))
  const combined = Buffer.concat([nonce, Buffer.from(created), Buffer.from(wssecPass, 'utf8')]);
  const passwordDigest = crypto
    .createHash('sha1')
    .update(combined)
    .digest('base64');

  return {
    'wsse:Security': {
      $: {
        'xmlns:wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
        'xmlns:wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
      },
      'wsse:UsernameToken': {
        $: {
          'wsu:Id': `UsernameToken-${crypto.randomBytes(8).toString('hex')}`
        },
        'wsse:Username': wssecUser,
        'wsse:Password': [
          {
            _: passwordDigest,
            $: {
              Type: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest'
            }
          }
        ],
        'wsse:Nonce': [
          {
            _: nonceB64,
            $: {
              EncodingType: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'
            }
          }
        ],
        'wsu:Created': created
      }
    }
  };
}

/**
 * Returns the appropriate SOAP content type header based on the SOAP version.
 * @param {string} soapVersion - SOAP version ('1.1' or '1.2').
 * @returns {string} - The content type string.
 */
function getSoapContentType(soapVersion) {
  return soapVersion === '1.2'
    ? 'application/soap+xml; charset=UTF-8'
    : 'text/xml; charset=UTF-8';
}

/**
 * Builds the SOAPAction header value if not explicitly provided by the caller.
 * @param {string} soapMethod - The SOAP operation name.
 * @param {string} namespace - The SOAP namespace.
 * @param {string} soapVersion - SOAP version ('1.1' or '1.2').
 * @returns {string} - The derived SOAPAction.
 */
function buildSoapAction(soapMethod, namespace, soapVersion) {
  // For SOAP 1.2, the action is often namespace + method.
  // For SOAP 1.1, the same approach may be used, though actual WSDLs can vary.
  return `${namespace}${soapMethod}`;
}

/**
 * Configures an Axios instance with retry/backoff logic and optional Basic Auth.
 * @param {Object} options
 * @param {number} options.soapTimeout - The request timeout in milliseconds.
 * @param {number} options.retryCount - The number of retry attempts.
 * @param {string} options.correlationId - Correlation ID for logging.
 * @param {string} [options.basicUser] - Basic Auth username.
 * @param {string} [options.basicPass] - Basic Auth password.
 * @returns {AxiosInstance} - The configured Axios instance.
 */
function configureAxiosWithRetry({
  soapTimeout,
  retryCount,
  correlationId,
  basicUser,
  basicPass
}) {
  const instance = axios.create({
    timeout: soapTimeout
  });

  // Optional Basic Auth configuration
  if (basicUser && basicPass) {
    const token = Buffer.from(`${basicUser}:${basicPass}`).toString('base64');
    instance.defaults.headers['Authorization'] = `Basic ${token}`;
  }

  // Sets up axios-retry
  axiosRetry(instance, {
    retries: retryCount,
    retryDelay: (count) => axiosRetry.exponentialDelay(count),
    retryCondition: (error) => {
      // Retries on network errors or 5xx responses
      return axiosRetry.isNetworkError(error) ||
        (error.response && error.response.status >= 500);
    },
    onRetry: (count, error, reqConfig) => {
      console.warn(JSON.stringify({
        level: 'WARN',
        correlationId,
        message: `Retry attempt ${count} for ${reqConfig.url} due to ${error.message}`
      }));
    }
  });

  return instance;
}

/**
 * Parses the SOAP response. If the response is not valid XML, checks for JSON or a SOAP Fault.
 * @param {string} soapResponseData - The SOAP response as text.
 * @param {string} correlationId - Correlation ID for logging.
 * @returns {Promise<Object>} - The parsed response object.
 */
async function safeParseSoapResponse(soapResponseData, correlationId) {
  const trimmed = soapResponseData.trim();

  // Checks for JSON fallback in case the server is misconfigured or returning JSON
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
      (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      const parsedJson = JSON.parse(trimmed);
      return { jsonFallback: parsedJson };
    } catch (jsonErr) {
      // If JSON parse fails, proceed to XML parse logic
    }
  }

  // Attempts normal XML parse
  try {
    return await parseStringPromise(soapResponseData);
  } catch (parseError) {
    console.warn(JSON.stringify({
      level: 'WARN',
      correlationId,
      message: 'Failed to parse SOAP response as XML; searching for SOAP Fault in raw text',
      parseError: parseError.message
    }));

    // Checks for a SOAP Fault pattern in raw text
    const faultRegex = /<soap:Fault|<SOAP-ENV:Fault(.|\s)*?<\/soap:Fault>|<\/SOAP-ENV:Fault>/i;
    if (faultRegex.test(soapResponseData)) {
      throw createError('SOAP Fault encountered (unparsed). Check raw SOAP response.', 502);
    }

    // If no visible fault, re-throw the parse error
    throw createError(`Failed to parse SOAP response: ${parseError.message}`, 502);
  }
}

/**
 * Extracts the result from the parsed SOAP response, or detects a SOAP Fault if present.
 * @param {Object} parsedResponse - The parsed SOAP response.
 * @param {string} soapMethod - The SOAP operation name.
 * @returns {any} - The extracted result, or an error if a fault is detected.
 */
function extractSoapResult(parsedResponse, soapMethod) {
  // Returns JSON fallback if the response was identified as JSON
  if (parsedResponse.jsonFallback) {
    return parsedResponse.jsonFallback;
  }

  if (!parsedResponse) {
    throw createError('Parsed SOAP response is empty.', 502);
  }

  const envelope =
    parsedResponse['soap:Envelope'] ||
    parsedResponse['SOAP-ENV:Envelope'] ||
    parsedResponse['env:Envelope'] ||
    null;

  if (!envelope) {
    throw createError('SOAP Envelope missing in response.', 502);
  }

  const body =
    envelope['soap:Body'] ||
    envelope['SOAP-ENV:Body'] ||
    envelope['env:Body'] ||
    null;

  if (!body) {
    throw createError('SOAP Body missing in response.', 502);
  }

  // Detects a SOAP Fault
  const fault =
    body['soap:Fault'] ||
    body['SOAP-ENV:Fault'] ||
    body['env:Fault'] ||
    null;

  if (fault) {
    const faultString = Array.isArray(fault)
      ? fault[0]?.faultstring?.[0] || 'Unknown SOAP Fault'
      : fault.faultstring?.[0] || 'Unknown SOAP Fault';

    throw createError(`SOAP Fault encountered: ${faultString}`, 502);
  }

  // Finds an operation-specific response node, e.g. <soapMethod>Response>
  const responseKey = Object.keys(body).find(key =>
    key.toLowerCase().includes(`${soapMethod.toLowerCase()}response`)
  );
  if (!responseKey) {
    throw createError(`Cannot find ${soapMethod}Response in SOAP body.`, 502);
  }

  const responseObj = Array.isArray(body[responseKey]) ? body[responseKey][0] : body[responseKey];
  if (!responseObj) {
    throw createError(`Empty ${soapMethod}Response object in SOAP body.`, 502);
  }

  // Checks for a nested <soapMethod>Result> node
  const resultKey = Object.keys(responseObj).find(key =>
    key.toLowerCase().includes(`${soapMethod.toLowerCase()}result`)
  );
  if (!resultKey) {
    // Returns the entire response if no explicit result is found
    return responseObj;
  }

  const resultNode = Array.isArray(responseObj[resultKey])
    ? responseObj[resultKey][0]
    : responseObj[resultKey];

  return resultNode;
}

/**
 * Provides a truncated preview of the result in the logs to avoid large output.
 * @param {any} result - The result object or string to preview.
 * @returns {string} - A short preview of the result.
 */
function previewResult(result) {
  const str = (typeof result === 'string') ? result : JSON.stringify(result);
  return str.length > 300
    ? `${str.substring(0, 300)}... [truncated]`
    : str;
}

/**
 * Creates an Error with a custom message and a statusCode field for handling in the callback.
 * @param {string} message - The error message.
 * @param {number} [statusCode=500] - The HTTP-like status code.
 * @returns {Error} - The customized error object.
 */
function createError(message, statusCode = 500) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}
