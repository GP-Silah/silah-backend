export class CreateCardDto {
    cardNumber: string;
    cardHolderName: string;
    expMonth: number;
    expYear: number;
}
//? No need for this dto as we are using tokenization, correct?
