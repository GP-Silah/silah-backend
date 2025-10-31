import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';

@Injectable()
export class WathqService {
    private client: AxiosInstance;

    constructor() {
        // Base URL for sandbox or production
        this.client = axios.create({
            baseURL: 'https://api.wathq.sa/sandbox',
            timeout: 10000,
        });
    }

    /**
     * Get basic commercial registration info by CR or entity number
     */
    async getBasicInfo(id: string, language: 'ar' | 'en' = 'en') {
        try {
            const response = await this.client.get(
                `/commercial-registration/info/${id}`,
                {
                    headers: {
                        apiKey: process.env.WATHQ_CONSUMER_KEY,
                        accept: 'application/json',
                    },
                    params: { language },
                },
            );

            return response.data;
        } catch (err: any) {
            const res = err.response;

            if (res) {
                const code = res.data?.code;

                // Handle "No Results Found" gracefully
                if (code === '404.2.1') {
                    return null; // No such CRN
                }

                // Optional: handle known business error codes more nicely
                if (code?.startsWith('400.')) {
                    throw new HttpException(
                        res.data.message || 'Invalid request to Wathq',
                        HttpStatus.BAD_REQUEST,
                    );
                }

                if (String(code).startsWith('500')) {
                    console.warn(`[Wathq] Provider internal error: ${code}`);
                    throw new HttpException(
                        'Temporary issue with provider',
                        HttpStatus.BAD_GATEWAY,
                    );
                }
            }

            console.log(err);
            throw new HttpException(
                'Failed to contact Wathq service',
                HttpStatus.INTERNAL_SERVER_ERROR,
            );
        }
    }
}
