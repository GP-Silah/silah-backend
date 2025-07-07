// prisma/seed.ts
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function main() {
    const parentCategories = [
        'Agricultural & Pet Supplies',
        'Beauty & Personal Care',
        'Fashion & Accessories',
        'Food, Beverages & Health',
        'Home & Living',
        'Hardware & Tools',
        'Packaging & Raw Materials',
        'Energy & Sustainability',
        'Business & Marketing Services',
        'Software & IT Solutions',
        'Shipping & Logistics',
        'Design Services',
        'Manufacturing & Packaging',
        'Technical & Repair Services',
        'Legal & Compliance Services',
    ];

    const parentMap = new Map<string, number>();
    for (const name of parentCategories) {
        const category = await prisma.category.upsert({
            where: { name },
            update: {},
            create: { name },
        });
        parentMap.set(name, category.id);
    }

    const childCategories = [
        { name: 'Animal Feed', parent: 'Agricultural & Pet Supplies' },
        { name: 'Fertilizers', parent: 'Agricultural & Pet Supplies' },
        {
            name: 'Pet Accessories & Toys',
            parent: 'Agricultural & Pet Supplies',
        },
        { name: 'Pet Food & Treats', parent: 'Agricultural & Pet Supplies' },

        { name: 'Skincare & Body Care', parent: 'Beauty & Personal Care' },
        { name: 'Hair Care', parent: 'Beauty & Personal Care' },
        { name: 'Personal Hygiene', parent: 'Beauty & Personal Care' },
        { name: 'Makeup & Fragrances', parent: 'Beauty & Personal Care' },

        { name: 'Furniture', parent: 'Home & Living' },
        { name: 'Household & Cleaning Supplies', parent: 'Home & Living' },
        { name: 'Kitchen & Dining', parent: 'Home & Living' },

        { name: 'Power Tools', parent: 'Hardware & Tools' },
        { name: 'Industrial Equipment', parent: 'Hardware & Tools' },

        { name: 'Snacks & Beverages', parent: 'Food, Beverages & Health' },
        {
            name: 'Dairy & Dairy Alternatives',
            parent: 'Food, Beverages & Health',
        },
        { name: 'Health Supplements', parent: 'Food, Beverages & Health' },

        { name: 'Clothing', parent: 'Fashion & Accessories' },
        { name: 'Jewelry & Watches', parent: 'Fashion & Accessories' },
        { name: 'Footwear', parent: 'Fashion & Accessories' },

        { name: 'Bottles & Containers', parent: 'Packaging & Raw Materials' },
        { name: 'Textiles & Fabrics', parent: 'Packaging & Raw Materials' },
        { name: 'Dyes & Chemicals', parent: 'Packaging & Raw Materials' },

        { name: 'Eco-Friendly Materials', parent: 'Energy & Sustainability' },
        {
            name: 'Renewable Energy Products',
            parent: 'Energy & Sustainability',
        },

        {
            name: 'Business Consulting',
            parent: 'Business & Marketing Services',
        },
        {
            name: 'Online Marketing & Ad Creation',
            parent: 'Business & Marketing Services',
        },

        { name: 'Web & App Development', parent: 'Software & IT Solutions' },
        { name: 'IT & Cloud Services', parent: 'Software & IT Solutions' },

        { name: 'Freight & Warehousing', parent: 'Shipping & Logistics' },
        { name: 'International Shipping', parent: 'Shipping & Logistics' },

        { name: 'Product Design', parent: 'Design Services' },
        { name: 'Logo & Branding Design', parent: 'Design Services' },
        { name: 'UI/UX & Graphic Design', parent: 'Design Services' },

        {
            name: 'Packaging & Co-Packaging',
            parent: 'Manufacturing & Packaging',
        },
        { name: 'Sourcing & Procurement', parent: 'Manufacturing & Packaging' },

        {
            name: 'General & Computer Repair',
            parent: 'Technical & Repair Services',
        },
        {
            name: 'Industrial Maintenance',
            parent: 'Technical & Repair Services',
        },

        {
            name: 'Business Legal Consulting',
            parent: 'Legal & Compliance Services',
        },
        {
            name: 'Tax & Regulatory Compliance',
            parent: 'Legal & Compliance Services',
        },
    ];

    for (const child of childCategories) {
        const parentId = parentMap.get(child.parent);
        if (!parentId)
            throw new Error(`Parent category not found: ${child.parent}`);

        await prisma.category.upsert({
            where: { name: child.name },
            update: {},
            create: {
                name: child.name,
                parentCategoryId: parentId,
            },
        });
    }
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(() => prisma.$disconnect());
