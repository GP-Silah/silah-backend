import { Injectable } from '@nestjs/common';
import axios from 'axios';

@Injectable()
export class TranslationService {
    /** DeepL API key from environment variables */
    private readonly apiKey = process.env.DEEPL_API_KEY;

    /** Base URL for DeepL free-tier API */
    private readonly baseUrl = 'https://api-free.deepl.com/v2/translate';

    /**
     * Translates a given text using DeepL API.
     *
     * @param {string} text - The text to translate.
     * @param {string} targetLang - Target language code (e.g., 'EN', 'AR', 'FR').
     * @param {string} [sourceLang] - Optional source language code.
     * @returns {Promise<string>} Translated text. Returns original text on failure.
     *
     * @example
     * const translated = await translationService.translateText('Hello', 'AR');
     * console.log(translated); // "مرحبا"
     */
    async translateText(
        text: string,
        targetLang: string,
        sourceLang?: string,
    ): Promise<string> {
        if (!text) return text;

        const params: any = {
            auth_key: this.apiKey,
            text,
            target_lang: targetLang.toUpperCase(), // e.g., 'EN', 'AR', 'FR'
        };
        if (sourceLang) {
            params.source_lang = sourceLang.toUpperCase();
        }

        try {
            const response = await axios.post(this.baseUrl, null, { params });
            return response.data.translations[0].text;
        } catch (err) {
            console.error(
                'DeepL translation error:',
                err.response?.data || err.message,
            );
            return text; // fallback: return original text
        }
    }
}
