import { Test, TestingModule } from '@nestjs/testing';
import {
    BadRequestException,
    InternalServerErrorException,
} from '@nestjs/common';
import { FileService } from './file.service';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import * as fileType from 'file-type';

// Create mocks at the top level
const mockS3Send = jest.fn();
const mockS3Client = {
    send: mockS3Send,
};

// Mock AWS SDK and file-type
jest.mock('@aws-sdk/client-s3', () => ({
    S3Client: jest.fn(() => mockS3Client),
    PutObjectCommand: jest.fn((input) => ({ input })),
    GetObjectCommand: jest.fn((input) => ({ input })),
}));

jest.mock('@aws-sdk/s3-request-presigner');

// Mock file-type module to match the import style
jest.mock('file-type', () => ({
    fromBuffer: jest.fn(),
}));

describe('FileService', () => {
    let service: FileService;
    let mockFileTypeFromBuffer: jest.Mock;

    beforeEach(async () => {
        // Get reference to the mocked fromBuffer function
        mockFileTypeFromBuffer = fileType.fromBuffer as jest.Mock;

        const module: TestingModule = await Test.createTestingModule({
            providers: [FileService],
        }).compile();

        service = module.get<FileService>(FileService);

        // Set up environment variables
        process.env.R2_ENDPOINT = 'https://test.r2.dev';
        process.env.R2_ACCESS_KEY_ID = 'test-key';
        process.env.R2_SECRET_ACCESS_KEY = 'test-secret';
        process.env.R2_BUCKET_NAME = 'test-bucket';
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('uploadFile', () => {
        const createMockFile = (
            overrides: Partial<Express.Multer.File> = {},
        ): Express.Multer.File => ({
            fieldname: 'file',
            originalname: 'test.jpg',
            encoding: '7bit',
            mimetype: 'image/jpeg',
            size: 1024,
            buffer: Buffer.from('fake-image-data'),
            destination: '',
            filename: '',
            path: '',
            stream: null as any,
            ...overrides,
        });

        it('should upload a valid image file successfully', async () => {
            const mockFile = createMockFile();
            mockS3Send.mockResolvedValue({});
            mockFileTypeFromBuffer.mockResolvedValue({
                mime: 'image/jpeg',
                ext: 'jpg',
            });

            const result = await service.uploadFile(mockFile);

            expect(result).toMatch(/^test-.+\.jpg$/);
            expect(mockS3Send).toHaveBeenCalledTimes(1);

            // Check that PutObjectCommand was called with correct parameters
            const command = mockS3Send.mock.calls[0][0];
            expect(command.input).toEqual(
                expect.objectContaining({
                    Bucket: 'test-bucket',
                    Key: expect.stringMatching(/^test-.+\.jpg$/),
                    ContentType: 'image/jpeg',
                    Body: mockFile.buffer,
                }),
            );
        });

        it('should throw BadRequestException when no file provided', async () => {
            await expect(service.uploadFile(null as any)).rejects.toThrow(
                new BadRequestException('No file provided'),
            );
        });

        it('should throw BadRequestException when file exceeds size limit', async () => {
            const mockFile = createMockFile({
                size: 6 * 1024 * 1024, // 6MB (exceeds 5MB default)
            });

            await expect(service.uploadFile(mockFile)).rejects.toThrow(
                new BadRequestException('File size exceeds 5 MB limit'),
            );
        });

        it('should respect custom MAX_UPLOAD_BYTES environment variable', async () => {
            process.env.MAX_UPLOAD_BYTES = '1048576'; // 1MB
            const mockFile = createMockFile({
                size: 2 * 1024 * 1024, // 2MB
            });

            await expect(service.uploadFile(mockFile)).rejects.toThrow(
                new BadRequestException('File size exceeds 1 MB limit'),
            );

            // Clean up
            delete process.env.MAX_UPLOAD_BYTES;
        });

        it('should throw BadRequestException for non-image files', async () => {
            const mockFile = createMockFile({
                originalname: 'test.pdf',
                mimetype: 'application/pdf',
            });
            mockFileTypeFromBuffer.mockResolvedValue({
                mime: 'application/pdf',
                ext: 'pdf',
            });

            await expect(service.uploadFile(mockFile)).rejects.toThrow(
                new BadRequestException(
                    'Only JPEG, PNG, and WEBP files are allowed',
                ),
            );
        });

        it('should throw BadRequestException when file type cannot be detected', async () => {
            const mockFile = createMockFile();
            mockFileTypeFromBuffer.mockResolvedValue(null);

            await expect(service.uploadFile(mockFile)).rejects.toThrow(
                new BadRequestException('Unable to determine file type'),
            );
        });

        it('should handle PNG files correctly', async () => {
            const mockFile = createMockFile({
                originalname: 'test.png',
                mimetype: 'image/png',
            });
            mockFileTypeFromBuffer.mockResolvedValue({
                mime: 'image/png',
                ext: 'png',
            });
            mockS3Send.mockResolvedValue({});

            const result = await service.uploadFile(mockFile);

            expect(result).toMatch(/^test-.+\.png$/);
            expect(mockS3Send).toHaveBeenCalledTimes(1);

            // Check that PutObjectCommand was called with correct parameters
            const command = mockS3Send.mock.calls[0][0];
            expect(command.input).toEqual(
                expect.objectContaining({
                    ContentType: 'image/png',
                }),
            );
        });

        it('should handle WEBP files correctly', async () => {
            const mockFile = createMockFile({
                originalname: 'test.webp',
                mimetype: 'image/webp',
            });
            mockFileTypeFromBuffer.mockResolvedValue({
                mime: 'image/webp',
                ext: 'webp',
            });
            mockS3Send.mockResolvedValue({});

            const result = await service.uploadFile(mockFile);

            expect(result).toMatch(/^test-.+\.webp$/);
        });

        it('should sanitize filenames with special characters', async () => {
            const mockFile = createMockFile({
                originalname: 'test<>:"/\\|?*.jpg',
            });
            mockFileTypeFromBuffer.mockResolvedValue({
                mime: 'image/jpeg',
                ext: 'jpg',
            });
            mockS3Send.mockResolvedValue({});

            const result = await service.uploadFile(mockFile);

            expect(result).toMatch(/^test-.+\.jpg$/);
        });

        it('should handle empty/invalid filenames', async () => {
            const mockFile = createMockFile({
                originalname: '!@#$.jpg',
            });
            mockFileTypeFromBuffer.mockResolvedValue({
                mime: 'image/jpeg',
                ext: 'jpg',
            });
            mockS3Send.mockResolvedValue({});

            const result = await service.uploadFile(mockFile);

            expect(result).toMatch(/^file-.+\.jpg$/);
        });

        it('should limit filename length', async () => {
            const longName = 'a'.repeat(200) + '.jpg';
            const mockFile = createMockFile({
                originalname: longName,
            });
            mockFileTypeFromBuffer.mockResolvedValue({
                mime: 'image/jpeg',
                ext: 'jpg',
            });
            mockS3Send.mockResolvedValue({});

            const result = await service.uploadFile(mockFile);

            // Should be truncated to 100 chars + UUID + extension
            expect(result.length).toBeLessThan(200);
            expect(result).toMatch(/^a+-.+\.jpg$/);
        });

        it('should throw InternalServerErrorException when S3 upload fails', async () => {
            const mockFile = createMockFile();
            mockFileTypeFromBuffer.mockResolvedValue({
                mime: 'image/jpeg',
                ext: 'jpg',
            });
            mockS3Send.mockRejectedValue(new Error('S3 Error'));

            await expect(service.uploadFile(mockFile)).rejects.toThrow(
                new InternalServerErrorException(
                    'Failed to upload file to storage provider',
                ),
            );
        });
    });

    describe('getFileUrl', () => {
        it('should generate signed URL for file', async () => {
            const mockUrl = 'https://signed-url.example.com';
            (getSignedUrl as jest.Mock).mockResolvedValue(mockUrl);

            const result = await service.getFileUrl('test-file.jpg');

            expect(result).toBe(mockUrl);
            expect(getSignedUrl).toHaveBeenCalledWith(
                expect.any(Object), // S3 client
                expect.any(Object), // GetObjectCommand
                { expiresIn: 3600 },
            );
        });

        it('should handle URL generation errors', async () => {
            (getSignedUrl as jest.Mock).mockRejectedValue(
                new Error('URL generation failed'),
            );

            await expect(service.getFileUrl('test-file.jpg')).rejects.toThrow(
                'URL generation failed',
            );
        });
    });
});
