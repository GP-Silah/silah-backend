import {
    BadRequestException,
    Injectable,
    InternalServerErrorException,
} from '@nestjs/common';
import {
    S3Client,
    PutObjectCommand,
    GetObjectCommand,
} from '@aws-sdk/client-s3';
import { v4 as uuid } from 'uuid';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import * as fileType from 'file-type';
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

        // Size validation
        const maxBytes = parseInt(
            process.env.MAX_UPLOAD_BYTES || `${5 * 1024 * 1024}`,
        ); // 5MB default
        if (file.size > maxBytes) {
            throw new BadRequestException(
                `File size exceeds ${Math.floor(maxBytes / 1024 / 1024)} MB limit`,
            );
        }

        // Detect file type using magic numbers
        const detectedType = await fileType.fromBuffer(file.buffer);
        if (!detectedType) {
            throw new BadRequestException('Unable to determine file type');
        }

        const allowedMime = ['image/jpeg', 'image/png', 'image/webp'];
        if (!allowedMime.includes(detectedType.mime)) {
            throw new BadRequestException(
                'Only JPEG, PNG, and WEBP files are allowed',
            );
        }

        // Sanitize filename
        let baseName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '');
        if (!baseName || baseName.startsWith('.')) {
            baseName = 'file' + '.' + detectedType.ext;
        }

        const ext = detectedType.ext;
        const truncated = baseName.slice(0, 100).replace(/\.[^.]+$/, ''); // remove original extension
        const finalName = `${truncated}-${uuid()}.${ext}`;

        try {
            await this.s3.send(
                new PutObjectCommand({
                    Bucket: process.env.R2_BUCKET_NAME,
                    Key: finalName,
                    Body: file.buffer,
                    ContentType: detectedType.mime,
                }),
            );
        } catch (e) {
            throw new InternalServerErrorException(
                'Failed to upload file to storage provider',
            );
        }

        return finalName;
    }
}
