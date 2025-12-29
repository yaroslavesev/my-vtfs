import {Context, Next} from "koa";
import {repository} from "@models/repository";
import {sendResponse} from "@api/middlewares/cruds/utils/sendResponse";

export async function unlink(ctx: Context, next: Next) {
    const token = String(ctx.query.token);
    const ino = parseInt(ctx.query.parent_ino as string, 10) || 0;

    console.log("[unlink] Incoming request:", { token, ino });

    const success = await repository.delete(ino, token);
    const bodyBuffer = Buffer.from(JSON.stringify({ success }), "utf8");

    await sendResponse(ctx, success ? 0 : -1, bodyBuffer);
    await next();
}