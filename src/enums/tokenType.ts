export enum TokenType {
    EMAIL_VERIFICATION = 'EMAIL_VERIFICATION',
    PASSWORD_RESET = 'PASSWORD_RESET',
    TOKEN = 'TOKEN', // We won't have access and refresh token, it is only one token stored for longtime in the database and as a cookie in the browser
}
