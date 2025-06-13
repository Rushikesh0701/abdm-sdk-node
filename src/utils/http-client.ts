import * as crypto from 'crypto';

import type { AxiosError, AxiosInstance, AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';

import type { ABDMConfig, APIResponse } from '../types';

import { logger } from './logger';

// Define a custom request config that includes our authToken property
interface CustomAxiosRequestConfig extends InternalAxiosRequestConfig {
  authToken?: string;
  requestId?: string;
  timestamp?: number;
  retryCount?: number;
}

interface AuthTokenResponse {
  accessToken: string;
  expiresIn: number;
  tokenType: string;
  // Error fields for OAuth2 error responses
  error?: string;
  error_description?: string;
  error_uri?: string;
}

// Define a type for the expected structure of ABDM API error responses
interface AbdmErrorData {
  error?: {
    code?: string;
    message?: string;
    details?: any[];
  };
  code?: string;
  message?: string;
  details?: any[];
}

export class HttpClient {
  private readonly client: AxiosInstance;
  public readonly config: ABDMConfig;
  private _authToken: string | null = null;
  private _tokenExpiry: Date | null = null;
  private _publicKey: string | null = null;
  private _privateKey: string | null = null;
  private _keyId: string | null = null;

  /**
   * Make a POST request with proper typing
   * @param url - The URL to make the request to
   * @param data - The request body data
   * @param config - Optional request configuration
   * @returns Promise with the API response
   */
  async post<T>(url: string, data: any, config?: AxiosRequestConfig): Promise<APIResponse<T>> {
    try {
      const response = await this.client.post(url, data, config);
      return response.data as APIResponse<T>;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const requestId = (error.config as CustomAxiosRequestConfig)?.requestId || 'unknown';
        logger.error(`[${requestId}] Axios error:`, error);
        const responseData = error.response?.data as APIResponse<T>;
        throw new Error(`API Error: ${responseData?.error?.message || error.message}`);
      }
      throw error;
    }
  }

  /**
   * Get the current authentication token
   */
  public get authToken(): string | null {
    return this._authToken;
  }

  /**
   * Set the authentication token
   */
  public set authToken(token: string | null) {
    this._authToken = token;
  }

  /**
   * Get the token expiry time
   */
  public get tokenExpiry(): Date | null {
    return this._tokenExpiry;
  }

  /**
   * Set the token expiry time
   */
  public set tokenExpiry(expiry: Date | null) {
    this._tokenExpiry = expiry;
  }

  /**
   * Get the current authentication token (legacy method)
   */
  public getAuthToken(): string | null {
    return this.authToken;
  }

  /**
   * Set the authentication token (legacy method)
   */
  public setAuthToken(token: string | null): void {
    this.authToken = token;
  }

  /**
   * Get the public key
   */
  public get publicKey(): string | null {
    return this._publicKey;
  }

  /**
   * Set the public key
   */
  public set publicKey(publicKey: string) {
    this._publicKey = publicKey;
  }

  /**
   * Get the private key
   */
  /**
   * Get the private key
   */
  public get privateKey(): string | null {
    return this._privateKey;
  }

  /**
   * Set the private key
   */
  public set privateKey(privateKey: string) {
    this._privateKey = privateKey;
  }

  /**
   * Get the key ID
   */
  public get keyId(): string | null {
    return this._keyId;
  }

  /**
   * Set the key ID
   */
  public set keyId(keyId: string) {
    this._keyId = keyId;
  }

  constructor(config: ABDMConfig) {
    this.config = {
      ...config,
      baseUrl: config.baseUrl || 'https://dev.abdm.gov.in/gateway',
      useSandbox: config.useSandbox !== false, // Default to true
      timeout: config.timeout || 30000,
    };

    this.client = axios.create({
      baseURL: this.config.baseUrl,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(config.headers || {}),
      },
    });

    // Add request interceptor for authentication and logging
    this.client.interceptors.request.use(
      async (config: InternalAxiosRequestConfig) => {
        const internalConfig = config as CustomAxiosRequestConfig;
        const authPathSegment = '/v3/auth/token';
        const requestId = Math.random().toString(36).substring(2, 8);
        internalConfig.requestId = requestId;
        internalConfig.timestamp = Date.now();

        // Log the request details
        logger.debug(`[${requestId}] === REQUEST START ===`);
        logger.debug(`[${requestId}] ${config.method?.toUpperCase()} ${config.url}`);
        logger.debug(`[${requestId}] Headers:`, {
          ...config.headers,
          'Authorization': config.headers?.Authorization ? 'Bearer ***' : undefined,
        });
        
        if (config.data) {
          logger.debug(`[${requestId}] Request Data:`, config.data);
        }

        // Skip auth for session creation requests
        if (internalConfig.url?.includes(authPathSegment)) {
          logger.debug(`[${requestId}] Auth endpoint - skipping auth header`);
          return config;
        }

        let currentToken = internalConfig.authToken || this._authToken;

        // Check if token is expired
        if (currentToken && this._tokenExpiry) {
          if (new Date() >= this._tokenExpiry) {
            logger.debug(`[${requestId}] Token expired at ${this._tokenExpiry.toISOString()}`);
            currentToken = null;
          } else {
            logger.debug(`[${requestId}] Using existing token (expires at ${this._tokenExpiry.toISOString()})`);
          }
        }

        // Try to authenticate if no valid token
        if (!currentToken && this.config.clientId && this.config.clientSecret) {
          logger.debug(`[${requestId}] No valid token - attempting to authenticate...`);
          try {
            await this.authenticate();
            currentToken = this._authToken;
            logger.debug(`[${requestId}] Successfully authenticated`);
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            logger.error(`[${requestId}] Failed to re-authenticate during request: ${errorMessage}`);
            // Continue without token, will fail with 401
          }
        } else if (!currentToken) {
          logger.debug(`[${requestId}] No credentials available for authentication`);
        }

        // Add Authorization header if we have a token
        if (currentToken) {
          internalConfig.headers.Authorization = `Bearer ${currentToken}`;
          logger.debug(`[${requestId}] Added Authorization header`);
        } else {
          logger.debug(`[${requestId}] No Authorization header added`);
        }

        return config;
      },
      (error) => {
        const requestId = (error.config as CustomAxiosRequestConfig)?.requestId || 'unknown';
        logger.error(`[${requestId}] Request interceptor error:`, error);
        return Promise.reject(error);
      }
    );

    // Add response interceptor for logging
    this.client.interceptors.response.use(
      (response) => {
        const requestId = (response.config as CustomAxiosRequestConfig)?.requestId || 'unknown';
        const duration = Date.now() - ((response.config as CustomAxiosRequestConfig)?.timestamp || 0);
        
        logger.debug(`[${requestId}] === RESPONSE RECEIVED (${duration}ms) ===`);
        logger.debug(`[${requestId}] Status: ${response.status} ${response.statusText}`);
        logger.debug(`[${requestId}] Headers:`, response.headers);
        
        if (response.data) {
          logger.debug(`[${requestId}] Response Data:`, response.data);
        }
        
        return response;
      },
      (error) => {
        const requestId = (error.config as CustomAxiosRequestConfig)?.requestId || 'unknown';
        const duration = error.config ? (Date.now() - ((error.config as CustomAxiosRequestConfig)?.timestamp || 0)) : 0;
        
        logger.error(`[${requestId}] === REQUEST FAILED (${duration}ms) ===`);
        
        if (error.response) {
          // The request was made and the server responded with a status code
          // that falls out of the range of 2xx
          logger.error(`[${requestId}] Error Status: ${error.response.status}`);
          logger.error(`[${requestId}] Error Headers:`, error.response.headers);
          logger.error(`[${requestId}] Error Data:`, error.response.data);
        } else if (error.request) {
          // The request was made but no response was received
          logger.error(`[${requestId}] No response received:`, error.request);
        } else {
          // Something happened in setting up the request that triggered an Error
          logger.error(`[${requestId}] Request setup error:`, error.message);
        }
        
        return Promise.reject(error);
      }
    );
  }

  /**
   * Authenticates with ABDM and stores the access token and its expiry.
   */
  public async authenticate(): Promise<void> {
    const requestId = Math.random().toString(36).substring(2, 8);
    
    if (!this.config.clientId || !this.config.clientSecret) {
      const error = new Error('Client ID and Client Secret are required for authentication');
      logger.error(`[${requestId}] Authentication error:`, error);
      throw error;
    }

    // Log the config being used for authentication
    logger.debug(`[${requestId}] === AUTHENTICATION CONFIGURATION ===`);
    logger.debug(`[${requestId}] Base URL: ${this.config.baseUrl}`);
    logger.debug(`[${requestId}] Sandbox Mode: ${this.config.useSandbox}`);
    logger.debug(`[${requestId}] Timeout: ${this.config.timeout}ms`);
    logger.debug(`[${requestId}] Client ID: ${this.config.clientId ? '*** (set)' : 'undefined'}`);
    logger.debug(`[${requestId}] Client Secret: ${this.config.clientSecret ? '*** (set)' : 'undefined'}`);
    logger.debug(`[${requestId}] X-CM-ID: ${(this.config as any).xcmId || 'sbx (default)'}`);

    // Use the v3 authentication endpoint for ABDM
    // Prefer authBaseURL if provided, otherwise fall back to baseUrl
    let authBaseURL = (this.config as any).authBaseURL || this.config.baseUrl;
    
    // Ensure the base URL doesn't end with a slash to avoid double slashes
    authBaseURL = authBaseURL.endsWith('/') ? authBaseURL.slice(0, -1) : authBaseURL;
    
    // Construct the authentication URL
    const authUrl = `${authBaseURL}/v3/auth/token`;
    logger.debug(`[${requestId}] Authentication Endpoint: ${authUrl}`);
    
    // Log environment variables for debugging
    logger.debug(`[${requestId}] Environment Variables:`);
    Object.entries(process.env)
      .filter(([key]) => key.startsWith('ABHA_') || key === 'NODE_ENV')
      .forEach(([key, value]) => {
        const displayValue = key.includes('SECRET') || key.includes('KEY') 
          ? '*** (set)' 
          : value || 'undefined';
        logger.debug(`[${requestId}]   ${key}=${displayValue}`);
      });
    
    // Create Basic Auth header
    const authString = Buffer.from(
      `${this.config.clientId}:${this.config.clientSecret}`
    ).toString('base64');

    // Prepare form data for x-www-form-urlencoded
    const params = new URLSearchParams();
    params.append('grant_type', 'client_credentials');
    params.append('client_id', this.config.clientId);
    params.append('client_secret', this.config.clientSecret);

    // Create a custom request config with our additional properties
    const requestConfig: AxiosRequestConfig & { requestId?: string } = {
      url: authUrl,
      method: 'POST',
      data: params.toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${authString}`,
        'X-CM-ID': (this.config as any).xcmId || 'sbx',
      },
      // Always resolve the promise so we can handle all status codes
      validateStatus: () => true,
      // Add timeout to prevent hanging
      timeout: 30000, // Increased timeout to 30 seconds
      // Add request ID for tracing
      requestId,
      // Enable request/response interception for detailed logging
      transitional: {
        silentJSONParsing: false,
        forcedJSONParsing: false,
        clarifyTimeoutError: true,
      },
    };

    // Log the request details (with sensitive data masked)
    logger.debug(`[${requestId}] === AUTHENTICATION REQUEST ===`);
    logger.debug(`[${requestId}] URL: ${authUrl}`);
    logger.debug(`[${requestId}] Method: ${requestConfig.method}`);
    logger.debug(`[${requestId}] Headers:`, {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ***',
      'X-CM-ID': (this.config as any).xcmId || 'sbx',
    });
    logger.debug(`[${requestId}] Body:`, params.toString());
    logger.debug(`[${requestId}] Timeout: ${requestConfig.timeout}ms`);
    
    // Log the actual auth string for debugging (masked)
    logger.debug(`[${requestId}] Auth String (first 10 chars): Basic ${authString.substring(0, 10)}...`);
    
    // Log the full URL being used for the request
    logger.debug(`[${requestId}] Full Request URL: ${authUrl}`);
    
    // Log the environment variables for debugging
    logger.debug(`[${requestId}] Environment Variables:`, {
      NODE_ENV: process.env['NODE_ENV'],
      ABHA_CLIENT_ID: process.env['ABHA_CLIENT_ID'] ? '***' : 'not set',
      ABHA_CLIENT_SECRET: process.env['ABHA_CLIENT_SECRET'] ? '***' : 'not set',
      LOG_LEVEL: process.env['LOG_LEVEL'] || 'info',
      NODE_TLS_REJECT_UNAUTHORIZED: process.env['NODE_TLS_REJECT_UNAUTHORIZED'] || 'not set',
    });

    // Log the full request details (with sensitive data masked)
    logger.debug('Sending authentication request:', {
      url: authUrl,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ***',
        'X-CM-ID': (this.config as any).xcmId || 'sbx',
      },
      data: 'grant_type=client_credentials&client_id=***&client_secret=***',
      fullUrl: authUrl,
      authHeader: `Basic ${authString.substring(0, 10)}...`
    });

    try {
      logger.debug('Sending HTTP request to:', authUrl);
      const startTime = Date.now();
      const response = await axios.request<AuthTokenResponse>(requestConfig);
      const duration = Date.now() - startTime;

      // Log response details
      const responseData = response.data || {};
      const responseDetails = {
        status: response.status,
        statusText: response.statusText,
        duration: `${duration}ms`,
        headers: response.headers,
        data: responseData,
        config: {
          url: response.config?.url,
          method: response.config?.method,
          headers: {
            ...response.config?.headers,
            Authorization: '***',
          },
        },
      };
      
      logger.debug('Authentication response received:', responseDetails);

      if (response.status !== 200) {
        const errorDetails = {
          status: response.status,
          statusText: response.statusText,
          error: responseData.error || 'Unknown error',
          errorDescription: responseData.error_description || 'No error description provided',
          timestamp: new Date().toISOString(),
          request: {
            url: response.config?.url,
            method: response.config?.method,
            headers: {
              ...response.config?.headers,
              Authorization: '***',
            },
          },
          response: {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
            data: responseData,
          },
        };

        // Log the full error details for debugging
        logger.error('Authentication failed with status:', JSON.stringify(errorDetails, null, 2));
        
        // Provide more specific error messages based on the status code
        let errorMessage = `Authentication failed with status ${response.status}`;
        if (responseData.error_description) {
          errorMessage += `: ${responseData.error_description}`;
        } else if (responseData.error) {
          errorMessage += `: ${responseData.error}`;
        } else if (response.status === 401) {
          errorMessage = 'Invalid client credentials or authentication failed. Please verify your client ID and secret.';
        } else if (response.status === 400) {
          errorMessage = 'Invalid request. Please check your request parameters';
        } else if (response.status === 404) {
          errorMessage = 'Authentication endpoint not found. Please check the base URL and authentication endpoint.';
        } else if (response.status >= 500) {
          errorMessage = 'Server error occurred while authenticating. Please try again later.';
        } else {
          // For any other status code, include the response data in the error message
          errorMessage += `: ${JSON.stringify(responseData, null, 2)}`;
        }
        
        // Include the request URL in the error message for easier debugging
        errorMessage += `\nRequest URL: ${response.config?.url}`;
        
        // Create a more detailed error object
        const error = new Error(errorMessage);
        (error as any).status = response.status;
        (error as any).response = response;
        
        throw error;
      }

      const { accessToken, expiresIn } = response.data;
      if (!accessToken) {
        throw new Error('No access token received in response');
      }

      this._authToken = accessToken;
      this._tokenExpiry = new Date(Date.now() + (expiresIn - 300) * 1000);
      
      logger.info('Successfully authenticated with ABDM API');
    } catch (error: unknown) {
      let errorMessage: string;
      if (axios.isAxiosError(error)) {
        const responseData = error.response?.data || {};
        errorMessage = responseData.error?.message || 
                      responseData.message || 
                      error.message || 
                      'Unknown authentication error';
        
        logger.error('ABDM Authentication Error:', {
          status: error.response?.status,
          statusText: error.response?.statusText,
          data: responseData,
          headers: error.config?.headers ? {
            ...error.config.headers,
            'X-HIU-ID': '***',
            'X-HIU-Client-Key': '***',
            'Content-Type': error.config.headers['Content-Type']
          } : {}
        });
      } else if (error instanceof Error) {
        errorMessage = error.message;
      } else {
        errorMessage = 'An unexpected error occurred during authentication.';
      }
      logger.error('Authentication failed:', errorMessage);
      throw new Error(`Authentication failed: ${errorMessage}`);
    }
  }

  /**
   * Encrypts data using the ABDM public key.
   * @param data The string data to encrypt.
   * @returns The Base64-encoded encrypted string.
   */
  public encrypt(data: string): string {
    if (!this._publicKey) {
      throw new Error('Public key is not set. Cannot encrypt data.');
    }
    try {
      const buffer = Buffer.from(data, 'utf8');
      const encrypted = crypto.publicEncrypt(
        {
          key: this._publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        buffer
      );
      return encrypted.toString('base64');
    } catch (error: unknown) {
      logger.error('Encryption failed:', error);
      if (error instanceof Error) {
        throw new Error(`Encryption failed: ${error.message}`);
      }
      throw new Error('An unknown error occurred during encryption.');
    }
  }

  /**
   * The core request method for all HTTP calls.
   * @param config The Axios request config.
   * @returns A standardized APIResponse object.
   */
  private async request<T>(config: AxiosRequestConfig): Promise<APIResponse<T>> {
    const requestId = Math.random().toString(36).substring(2, 8);
    const startTime = Date.now();
    
    // Log the request details
    logger.debug(`[${requestId}] === STARTING REQUEST ===`);
    logger.debug(`[${requestId}] ${config.method?.toUpperCase() || 'GET'} ${config.url}`);
    logger.debug(`[${requestId}] Headers:`, {
      ...config.headers,
      Authorization: config.headers?.Authorization ? 'Bearer ***' : undefined,
    });
    
    if (config.data) {
      logger.debug(`[${requestId}] Request Data:`, config.data);
    }
    
    try {
      const response = await this.client.request<APIResponse<T>>({
        ...config,
        headers: {
          ...config.headers,
          'X-Request-ID': uuidv4(),
          'X-Timestamp': new Date().toISOString(),
        },
      });
      
      const duration = Date.now() - startTime;
      logger.debug(`[${requestId}] === REQUEST COMPLETED (${duration}ms) ===`);
      logger.debug(`[${requestId}] Status: ${response.status} ${response.statusText}`);
      
      if (response.data) {
        logger.debug(`[${requestId}] Response Data:`, response.data);
      }
      
      return response.data;
    } catch (error) {
      const duration = Date.now() - startTime;
      const axiosError = error as AxiosError<APIResponse<T>>;
      
      logger.error(`[${requestId}] === REQUEST FAILED (${duration}ms) ===`);
      
      if (axiosError.response) {
        // The request was made and the server responded with a status code
        // that falls out of the range of 2xx
        logger.error(`[${requestId}] Error Status: ${axiosError.response.status}`);
        logger.error(`[${requestId}] Error Headers:`, axiosError.response.headers);
        logger.error(`[${requestId}] Error Data:`, axiosError.response.data);
      } else if (axiosError.request) {
        // The request was made but no response was received
        logger.error(`[${requestId}] No response received:`, axiosError.request);
      } else {
        // Something happened in setting up the request that triggered an Error
        logger.error(`[${requestId}] Request setup error:`, axiosError.message);
      }
      
      if (axios.isAxiosError(axiosError)) {
        throw this.normalizeError(axiosError);
      }
      throw error;
    }
  }

  /**
   * Normalize error response from Axios.
   * @param error The Axios error.
   * @returns A standardized error object.
   */
  private normalizeError(error: AxiosError<APIResponse<any>>): Error {
    const response = error.response?.data;
    const errorData: AbdmErrorData = (response as any)?.error || response || {};

    const errorMessage = errorData.message || errorData.error?.message || error.message;
    const errorCode = errorData.code || errorData.error?.code || 'UNKNOWN_ERROR';

    const normalizedError = new Error(`[${errorCode}] ${errorMessage}`) as any;
    normalizedError.code = errorCode;
    normalizedError.details = errorData.details || errorData.error?.details;

    if (error.response?.status) {
      normalizedError.status = error.response.status;
    }

    return normalizedError;
  }

  // --- HTTP Method Helpers ---

  public async get<T>(url: string, config?: AxiosRequestConfig): Promise<APIResponse<T>> {
    return this.request<T>({ ...config, method: 'GET', url });
  }

  public async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<APIResponse<T>> {
    return this.request<T>({ ...config, method: 'POST', url, data });
  }

  public async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<APIResponse<T>> {
    return this.request<T>({ ...config, method: 'PUT', url, data });
  }

  public async delete<T>(url: string, config?: AxiosRequestConfig): Promise<APIResponse<T>> {
    return this.request<T>({ ...config, method: 'DELETE', url });
  }

  public async patch<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<APIResponse<T>> {
    return this.request<T>({ ...config, method: 'PATCH', url, data });
  }
}
