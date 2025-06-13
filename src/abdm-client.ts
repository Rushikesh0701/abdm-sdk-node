// Internal services - not exposed publicly
import { M1Service } from './services/m1.service';
import { M2Service } from './services/m2.service';
import { M3Service } from './services/m3.service';
import type { ABDMConfig } from './types/common';
import { HttpClient } from './utils/http-client';

/**
 * Main client for interacting with the Ayushman Bharat Digital Mission (ABDM) APIs
 */
export class ABDMClient {
  private http: HttpClient;
  private m1: M1Service;
  private m2: M2Service;
  private m3: M3Service;

  /**
   * Create a new ABDM client
   * @param config - Configuration for the ABDM client
   */
  /**
   * Create a new ABDM client
   * @param config - Configuration for the ABDM client
   * @example
   * // Basic usage with required config
   * const client = new ABDMClient({
   *   clientId: 'your-client-id',
   *   clientSecret: 'your-client-secret',
   *   basePath: 'https://dev.abdm.gov.in/gateway', // optional
   *   useSandbox: true, // optional, defaults to true
   * });
   */
  constructor(config: ABDMConfig) {
    if (!config.clientId || !config.clientSecret) {
      throw new Error('clientId and clientSecret are required in the config object.');
    }

    // Set default values if not provided
    const effectiveConfig: ABDMConfig = {
      useSandbox: true,
      ...config,
    };

    // Set the baseURL based on the environment
    if (!effectiveConfig.baseURL) {
      effectiveConfig.baseURL = effectiveConfig.useSandbox 
        ? 'https://dev.abdm.gov.in/gateway' 
        : 'https://healthid.ndhm.gov.in/api';
    }
    
    // Set the authBaseURL specifically for authentication
    // For sandbox, use the gateway URL without the /v3 suffix
    if (!effectiveConfig.authBaseURL) {
      effectiveConfig.authBaseURL = effectiveConfig.useSandbox
        ? 'https://dev.abdm.gov.in/gateway'
        : 'https://healthid.ndhm.gov.in/api';
    }

    this.http = new HttpClient(effectiveConfig);
    this.m1 = new M1Service(this.http);
    this.m2 = new M2Service(this.http);
    this.m3 = new M3Service(this.http);
  }

  /**
   * Set a new authentication token
   * @param token - The authentication token
   * @param expiresIn - Optional time in seconds until the token expires (default: 1 hour)
   */
  public setAuthToken(token: string, expiresIn: number = 3600): void {
    if (!this.http) {
      throw new Error('HTTP client not initialized');
    }

    // Set the token using the public setter
    this.http.authToken = token;

    // Calculate expiry time (5 minutes before actual expiry to be safe)
    const expiryTime = Date.now() + (expiresIn - 300) * 1000;
    const expiryDate = new Date(expiryTime);

    // Set the expiry in the http client using the public setter
    this.http.tokenExpiry = expiryDate;
  }

  /**
   * Clear the current authentication token
   */
  public clearAuthToken(): void {
    if (this.http) {
      this.http.authToken = null;
      this.http.tokenExpiry = null;
    }
  }

  /**
   * Get the current authentication token
   * @returns The current authentication token or null if not authenticated
   */
  public getAuthToken(): string | null {
    return this.http.authToken;
  }

  /**
   * Check if the current token is valid
   * @returns True if the token is valid, false otherwise
   */
  public isTokenValid(): boolean {
    if (!this.http) {
      return false;
    }

    // Use the public getter methods
    const authToken = this.http.authToken;
    const tokenExpiry = this.http.tokenExpiry;

    // If we don't have a token or expiry, it's not valid
    if (!authToken || !tokenExpiry) {
      return false;
    }

    // Check if the token is expired
    // tokenExpiry is already a Date object, so we can compare directly
    const now = new Date();
    // Only log token refresh in non-test environments
    if (process.env['NODE_ENV'] === 'test') {
      // eslint-disable-next-line no-console
      process.stdout.write(`[isTokenValid] now: ${now.getTime()}, tokenExpiry: ${tokenExpiry?.getTime()}\n`);
    }
    return now < tokenExpiry;
  }

  /**
   * Authenticate with ABDM and get an access token
   * @returns A promise that resolves when authentication is complete
   */
  public async authenticate(): Promise<void> {
    await this.http.authenticate();
  }
}
