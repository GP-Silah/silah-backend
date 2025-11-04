import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import * as qs from 'qs';

@Injectable()
export class TranslationService {
    private readonly apiKey = process.env.DEEPL_API_KEY;
    private readonly baseUrl = 'https://api-free.deepl.com/v2/translate';
    private readonly logger = new Logger(TranslationService.name);

    /**
     * Translate a single text string
     */
    async translateText(
        text: string,
        targetLang: 'ar' | 'en',
        sourceLang?: string,
    ): Promise<string> {
        if (!text || !targetLang) return text;

        const params: any = {
            auth_key: this.apiKey,
            text,
            target_lang: targetLang.toUpperCase(),
        };
        if (sourceLang) params.source_lang = sourceLang.toUpperCase();

        try {
            const response = await axios.post(this.baseUrl, null, { params });
            return response.data.translations[0].text;
        } catch (err) {
            this.logger.error(
                `DeepL translation error (single): ${err.response?.data?.message || err.message}`,
            );
            return text;
        }
    }

    /** * Translate multiple texts in batches (avoids 429 Too Many Requests) */
    async translateBatch(
        texts: string[],
        targetLang: 'ar' | 'en',
        sourceLang?: string,
    ): Promise<string[]> {
        if (!texts?.length) return texts;

        this.logger.debug(`Translating batch of ${texts.length} texts`);

        const invalid = texts.filter(
            (t) => typeof t !== 'string' || !t.trim().length,
        );
        if (invalid.length > 0) {
            this.logger.warn(`⚠️ Found ${invalid.length} invalid texts:`);
            console.log(invalid);
        }

        const validTexts = texts.filter(
            (t) => typeof t === 'string' && t.trim().length > 0,
        );

        if (validTexts.length === 0) {
            this.logger.warn('⚠️ No valid texts to translate.');
            return texts;
        }

        const CHUNK_SIZE = 40;
        const results: string[] = [];

        for (let i = 0; i < validTexts.length; i += CHUNK_SIZE) {
            const chunk = validTexts.slice(i, i + CHUNK_SIZE);

            // ✅ Use application/x-www-form-urlencoded body, not query params
            const body = qs.stringify(
                {
                    auth_key: this.apiKey,
                    target_lang: targetLang.toUpperCase(),
                    ...(sourceLang && {
                        source_lang: sourceLang.toUpperCase(),
                    }),
                    text: chunk, // DeepL supports multiple "text" fields
                },
                { arrayFormat: 'repeat' },
            );

            try {
                const response = await axios.post(this.baseUrl, body, {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                });

                const translatedChunk = response.data.translations.map(
                    (t) => t.text,
                );
                results.push(...translatedChunk);

                if (i + CHUNK_SIZE < validTexts.length)
                    await new Promise((r) => setTimeout(r, 1000));
            } catch (err) {
                this.logger.error(
                    `DeepL translation error (batch): ${
                        err.response?.data?.message || err.message
                    }`,
                );
                results.push(...chunk);
            }
        }

        const translatedMap = new Map(
            validTexts.map((t, i) => [t, results[i] || t]),
        );
        return texts.map((t) => translatedMap.get(t) || t);
    }
}
