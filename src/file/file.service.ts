import { BadRequestException, Injectable, InternalServerErrorException } from '@nestjs/common';
import {
    S3Client,
    PutObjectCommand,
    GetObjectCommand,
} from '@aws-sdk/client-s3';
import { v4 as uuid } from 'uuid';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import * as path from 'path';
import { fileTypeFromBuffer } from 'file-type';

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

        // Configurable max size (default 5MB)
        const maxSize = parseInt(process.env.MAX_UPLOAD_BYTES || '', 10) || 5 * 1024 * 1024;
        if (file.size > maxSize) {
            throw new BadRequestException(`File size exceeds ${maxSize / (1024 * 1024)} MB limit`);
        }

        // Validate file content using magic numbers
        let detectedType;
        try {
            detectedType = await fileTypeFromBuffer(file.buffer);
        } catch (e) {
            throw new BadRequestException('Unable to determine file type');
        }
        // Accept only images (png, jpeg, webp, gif, svg, etc.)
        const allowedMime = [
            'image/png',
            'image/jpeg',
            'image/webp',
            'image/gif',
            'image/svg+xml',
            'image/bmp',
            'image/x-icon',
        ];
        // If file-type cannot detect (e.g., svg), fallback to mimetype check for svg only
        let mimeType = detectedType?.mime || file.mimetype;
        if (!allowedMime.includes(mimeType)) {
            // Special case: allow svg if mimetype is image/svg+xml
            if (!(file.mimetype === 'image/svg+xml' && file.originalname.endsWith('.svg'))) {
                throw new BadRequestException('Only image files are allowed');
            }
            mimeType = 'image/svg+xml';
        }

        // Sanitize and normalize base filename
        let baseName = path.parse(file.originalname).name;
        // Remove control characters, trim, and limit length
        baseName = baseName.replace(/[\x00-\x1F\x7F/\\:*?"<>|]/g, '').trim().slice(0, 100) || 'file';

        // Derive safe extension from detected/normalized mime type
        let ext = '';
        if (detectedType?.ext) {
            ext = detectedType.ext;
        } else if (mimeType === 'image/svg+xml') {
            ext = 'svg';
        } else {
            ext = (file.mimetype.split('/')[1] || 'img').split('+')[0];
        }

        const key = `${baseName}-${uuid()}.${ext}`;
        try {
            await this.s3.send(
                new PutObjectCommand({
                    Bucket: this.bucket,
                    Key: key,
                    Body: file.buffer,
                    ContentType: mimeType,
                }),
            );
        } catch (err) {
            throw new InternalServerErrorException('Failed to upload file to storage provider');
        }
        return key;
    }
}
