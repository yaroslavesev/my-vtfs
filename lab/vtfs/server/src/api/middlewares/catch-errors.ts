import { Context, Next } from "koa";
import ResponseApi from "../../models/response";
import App from "@errors/app";

export default async function catchErrors(ctx: Context, next: Next) {
    try {
        await next();
    } catch (error) {
        let response: any = error;

        console.log(error);
        if (!(error instanceof App)) {
            response = new App(
                'INTERNAL_SERVER_ERROR',
                'internal server error',
                500,
            );
        }

        ctx.status = response.httpStatus;
        ctx.body = new ResponseApi(
            null,
            response.code,
            response.message,
        );
    }
}
