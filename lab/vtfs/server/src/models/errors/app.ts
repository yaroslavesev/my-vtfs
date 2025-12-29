export default class App extends Error {
    public code: string;

    public httpStatus: number;

    public message: string;

    constructor(
        code: string,
        message: string,
        httpStatus = 400,
    ) {
        super();
        this.code = code;
        this.httpStatus = httpStatus;
        this.message = message;
    }
}
