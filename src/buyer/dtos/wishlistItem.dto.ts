import { ItemType } from 'src/enums/itemType';

// TODO: Come back to this after implemeting the Supplier, Product, Service, and maybe "Item" modules
export class WishlistItemDto {
    itemId: string;
    itemName: string;
    itemImagesUrl?: string[];
    itemPrice: number;
    categories: string[];
    itemType: ItemType;
    // supplier: SupplierResponseDto
}
