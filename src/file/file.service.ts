import { BadRequestException, Injectable } from '@nestjs/common';
import {
    S3Client,
    PutObjectCommand,
    GetObjectCommand,
} from '@aws-sdk/client-s3';
import { v4 as uuid } from 'uuid';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import * as path from 'path';

/**
 * Service for handling file storage and retrieval using Cloudflare R2 (S3-compatible API).
 * Provides methods for uploading images and generating signed URLs for file access.
 */
@Injectable()
export class FileService {
    private s3 = new S3Client({
        region: 'auto',
        endpoint: process.env.R2_ENDPOINT,
        credentials: {
            accessKeyId: process.env.R2_ACCESS_KEY_ID!,
            secretAccessKey: process.env.R2_SECRET_ACCESS_KEY!,
        },
    });
    private bucket: string = process.env.R2_BUCKET_NAME!;

    /**
     * Generates a signed URL for accessing a file stored in R2.
     *
     * @param {string} key - The unique key (filename) of the file in the bucket.
     * @returns {Promise<string>} A signed URL valid for 1 hour.
     *
     * @throws {Error} If the signing process fails.
     */
    async getFileUrl(key: string): Promise<string> {
        const command = new GetObjectCommand({
            Bucket: this.bucket,
            Key: key,
        });
        return getSignedUrl(this.s3, command, { expiresIn: 3600 }); // 1 hour
    }

    /**
     * Uploads an image file to the R2 bucket.
     *
     * @param {Express.Multer.File} file - The file to be uploaded.
     * @returns {Promise<string>} The unique key (filename) of the uploaded file in the bucket.
     *
     * @throws {BadRequestException} If:
     *  - No file is provided
     *  - File is not an image
     *  - File exceeds 5MB size limit
     * @throws {Error} If the upload to R2 fails.
     */
    async uploadFile(file: Express.Multer.File): Promise<string> {
        if (!file) {
            throw new BadRequestException('No file provided');
        }
        if (!file.mimetype.startsWith('image/')) {
            throw new BadRequestException('Only image files are allowed');
        }
        if (file.size > 5 * 1024 * 1024) {
            // 5 MB limit
            throw new BadRequestException('File size exceeds 5 MB limit');
        }
        const key = `${path.parse(file.originalname).name}-${uuid()}.${file.mimetype.split('/')[1]}`;
        await this.s3.send(
            new PutObjectCommand({
                Bucket: this.bucket,
                Key: key,
                Body: file.buffer,
                ContentType: file.mimetype,
            }),
        );
        return key;
    }
}
