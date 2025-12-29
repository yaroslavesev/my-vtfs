import {Context, Next} from "koa";
import {repository} from "@models/repository";
import {sendResponse} from "@api/middlewares/cruds/utils/sendResponse";

export async function read(ctx: Context, next: Next) {
    const token = String(ctx.query.token);
    const ino = parseInt(ctx.query.parent_ino as string, 10) || 0;

    console.log("[read] Incoming request:", { token, ino });

    const file = await repository.findByIno(ino, token);
    if (!file) {
        console.log("[read] File not found");
        await sendResponse(ctx, -1, Buffer.from("File not found", "utf8"));
        return;
    }

    const bodyBuffer = file.data || Buffer.alloc(0);
    await sendResponse(ctx, 0, bodyBuffer);
    await next();
}