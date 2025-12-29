export default class Response {
    public code: string;

    public result: object | null;

    public error: string | null;

    constructor(result: object | null = null, code: string = 'OK', error: string | null = null) {
        this.code = code;
        this.result = result;
        this.error = error;
    }
}
