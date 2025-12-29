import { Context, Next } from "koa";
import { repository } from "@models/repository";

export async function mkdir(ctx: Context, next: Next) {
    const token = String(ctx.query.token);
    const parentIno = parseInt(ctx.query.parent_ino as string, 10) || 0;
    const name = ctx.query.name as string;

    const newDirectory = await repository.create(token, parentIno, true, null, name);

    const buf = Buffer.alloc(8);
    buf.writeBigInt64LE(BigInt(newDirectory.ino));

    ctx.set("Content-Type", "application/octet-stream");
    ctx.set("Content-Length", buf.length.toString());
    ctx.status = 200;

    ctx.body = buf;
    await next();
}
