import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import { ServiceConfig } from '../types';
import logger from './logger';

export class HttpClient {
  private client: AxiosInstance;

  constructor(private config: ServiceConfig) {
    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'OpenDirectory-Integration-Service/1.0.0',
      },
    });

    this.setupAuth();
    this.setupInterceptors();
  }

  private setupAuth(): void {
    if (!this.config.authentication || this.config.authentication.type === 'none') {
      return;
    }

    const { type, credentials } = this.config.authentication;

    switch (type) {
      case 'basic':
        if (credentials?.username && credentials?.password) {
          this.client.defaults.auth = {
            username: credentials.username,
            password: credentials.password,
          };
        }
        break;
      case 'bearer':
        if (credentials?.token) {
          this.client.defaults.headers.common['Authorization'] = `Bearer ${credentials.token}`;
        }
        break;
      case 'api-key':
        if (credentials?.apiKey) {
          this.client.defaults.headers.common['X-API-Key'] = credentials.apiKey;
        }
        break;
    }
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        logger.debug(`Making ${config.method?.toUpperCase()} request to ${config.url}`);
        return config;
      },
      (error) => {
        logger.error('Request error:', error.message);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response: AxiosResponse) => {
        logger.debug(`Received ${response.status} response from ${response.config.url}`);
        return response;
      },
      (error) => {
        const errorMessage = error.response?.data?.message || error.message;
        logger.error(`Response error from ${this.config.name}:`, {
          status: error.response?.status,
          message: errorMessage,
          url: error.config?.url,
        });
        return Promise.reject(error);
      }
    );
  }

  async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.get<T>(url, config);
    return response.data;
  }

  async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.post<T>(url, data, config);
    return response.data;
  }

  async put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.put<T>(url, data, config);
    return response.data;
  }

  async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.delete<T>(url, config);
    return response.data;
  }

  async patch<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.patch<T>(url, data, config);
    return response.data;
  }

  async healthCheck(): Promise<boolean> {
    try {
      if (this.config.healthEndpoint) {
        await this.get(this.config.healthEndpoint);
        return true;
      }
      return false;
    } catch (error) {
      return false;
    }
  }
}