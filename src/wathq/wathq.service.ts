import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';

@Injectable()
export class WathqService {
    private client: AxiosInstance;
    private accessToken: string | null = null;

    constructor() {
        // Base URL for sandbox or production
        this.client = axios.create({
            baseURL: 'https://api.wathq.sa/sandbox',
            timeout: 10000,
        });
    }

    /**
     * Retrieve access token from Wathq API using Consumer Key & Secret
     */
    private async getToken(): Promise<string | null> {
        if (this.accessToken) return this.accessToken; // reuse token if exists

        try {
            const clientId = process.env.WATHQ_CONSUMER_KEY;
            const clientSecret = process.env.WATHQ_CONSUMER_SECRET;

            if (!clientId || !clientSecret) {
                throw new Error(
                    'WATHQ_CONSUMER_KEY and WATHQ_CONSUMER_SECRET must be defined',
                );
            }

            const response = await this.client.post(
                '/oauth/token', // token endpoint
                new URLSearchParams({
                    grant_type: 'client_credentials',
                    client_id: clientId,
                    client_secret: clientSecret,
                }),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                },
            );

            this.accessToken = response.data.access_token;
            return this.accessToken;
        } catch (err) {
            console.log(err.message);
            throw new HttpException(
                'Failed to get Wathq token',
                HttpStatus.INTERNAL_SERVER_ERROR,
            );
        }
    }

    /**
     * Get basic commercial registration info by CR or entity number
     */
    async getBasicInfo(id: string, language: 'ar' | 'en' = 'en') {
        const token = await this.getToken();

        try {
            const response = await this.client.get(
                `/commercial-registration/info/${id}`,
                {
                    headers: {
                        Authorization: `Bearer ${token}`,
                    },
                    params: { language },
                },
            );

            return response.data;
        } catch (err: any) {
            throw new HttpException(
                err.response?.data || 'Failed to fetch CRN info',
                err.response?.status || HttpStatus.INTERNAL_SERVER_ERROR,
            );
        }
    }
}
