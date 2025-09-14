import { Injectable } from '@nestjs/common';
import axios from 'axios';

@Injectable()
export class TapPaymentsService {
    /**
     * Creates a new customer in Tap Payments.
     *
     * Sends a POST request to the Tap Payments API with the provided customer information.
     *
     * @param {Object} data - Customer information.
     * @param {string} data.first_name - Customer's first name.
     * @param {string} [data.middle_name] - Customer's middle name (optional).
     * @param {string} [data.last_name] - Customer's last name (optional).
     * @param {string} data.email - Customer's email address.
     * @param {Object} [data.phone] - Customer's phone information (optional).
     * @param {string} data.phone.country_code - Country code of the phone number (e.g., '966').
     * @param {string} data.phone.number - Phone number without country code.
     *
     * @returns {Promise<string>} The ID of the newly created Tap customer.
     *
     * @throws {Error} Throws an error if the API request fails. The error message will contain
     * the response from Tap Payments if available, or the generic error message.
     *
     * @example
     * const customerId = await tapService.createCustomer({
     *   first_name: 'John',
     *   last_name: 'Doe',
     *   email: 'john.doe@example.com',
     *   phone: { country_code: '966', number: '500000000' },
     * });
     * console.log(customerId); // e.g., 'cus_123456789'
     */
    async createCustomer(data: {
        first_name: string;
        middle_name?: string;
        last_name?: string;
        email: string;
        phone?: { country_code: string; number: string };
    }) {
        try {
            const response = await axios.post(
                'https://api.tap.company/v2/customers/',
                data,
                {
                    headers: {
                        Authorization: `Bearer ${process.env.TAP_SECRET_KEY}`,
                        'Content-Type': 'application/json',
                    },
                },
            );
            return response.data.id;
        } catch (err: any) {
            console.error(err.response?.data || err.message);
            throw err;
        }
    }

    /**
     * Retrieves a card from Tap using customerId and cardId.
     * @param customerId Tap customer ID (cus_xxx)
     * @param cardId Tap card ID (card_xxx)
     * @returns The card object from Tap
     */
    async getCard(customerId: string, cardId: string) {
        try {
            const response = await axios.get(
                `https://api.tap.company/v2/card/${customerId}/${cardId}`,
                {
                    headers: {
                        accept: 'application/json',
                        Authorization: `Bearer ${process.env.TAP_SECRET_KEY}`,
                    },
                },
            );
            return response.data;
        } catch (err: any) {
            console.error(err.response?.data || err.message);
            throw new Error('Failed to fetch card from Tap');
        }
    }

    /**
     * Deletes a saved card in Tap Payments for a given customer.
     *
     * @param {string} customerId - The Tap customer ID (cus_xxx).
     * @param {string} cardId - The Tap card ID (card_xxx).
     * @returns {Promise<void>} Resolves if deletion succeeds, throws otherwise.
     */
    async deleteCard(customerId: string, cardId: string): Promise<void> {
        try {
            await axios.delete(
                `https://api.tap.company/v2/card/${customerId}/${cardId}`,
                {
                    headers: {
                        Authorization: `Bearer ${process.env.TAP_SECRET_KEY}`,
                        Accept: 'application/json',
                    },
                },
            );
        } catch (err: any) {
            console.error(err.response?.data || err.message);
            throw new Error('Failed to delete card from Tap');
        }
    }
}
