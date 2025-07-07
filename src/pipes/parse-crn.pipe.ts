import { PipeTransform, Injectable, BadRequestException } from '@nestjs/common';

@Injectable()
export class ParseCrnPipe implements PipeTransform {
    transform(value: string): string {
        if (!/^\d{10}$/.test(value)) {
            throw new BadRequestException('CRN must be a 10-digit number');
        }
        return value;
    }
}
