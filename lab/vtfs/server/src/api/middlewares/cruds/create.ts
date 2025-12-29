import {Context, Next} from "koa";
import {repository} from "@models/repository";
import {sendResponse} from "@api/middlewares/cruds/utils/sendResponse";

export async function create(ctx: Context, next: Next) {
    const token = String(ctx.query.token);
    const ino = parseInt(ctx.query.ino as string, 10) || 0;
    const name = ctx.query.name as string;

    let rawData = ctx.query.data;
    if (Array.isArray(rawData)) rawData = rawData[0] || "";
    const content = Buffer.from(rawData || "", "utf-8");

    console.log("[create] Incoming request:", {token, ino, name, dataLength: content.length});

    const newFile = await repository.create(token, ino, false, content, name);
    const bodyBuffer = Buffer.from(JSON.stringify({ino: newFile.ino}), "utf8");

    await sendResponse(ctx, 0, bodyBuffer);
    await next();
}