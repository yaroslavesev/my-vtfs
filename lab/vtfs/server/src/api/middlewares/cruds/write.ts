import {Context, Next} from "koa";
import {repository} from "@models/repository";
import {sendResponse} from "@api/middlewares/cruds/utils/sendResponse";

export async function write(ctx: Context, next: Next) {
    const token = String(ctx.query.token);
    const ino = parseInt(ctx.query.ino as string, 10) || 0;

    let rawData = ctx.query.data;
    console.log(rawData);
    if (Array.isArray(rawData)) rawData = rawData[0] || "";
    const content = Buffer.from(rawData || "", "utf-8");
    const data = {data: content, name: ctx.query.name as string | undefined};
    console.log("[write] Incoming request:", {token, ino, dataLength: content.length, name: data.name, data: data.data});

    const updatedFile = await repository.update(ino, token, data);
    const bodyBuffer = Buffer.from(JSON.stringify({success: !updatedFile}), "utf8");
    console.log(!updatedFile);
    await sendResponse(ctx, !updatedFile ? 0 : -1, bodyBuffer);
    await next();
}