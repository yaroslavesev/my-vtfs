import { Context } from "koa";


export async function sendResponse(ctx: Context, retVal: number, body?: Buffer) {
    const content = body ?? Buffer.alloc(0);
    console.log(retVal)
    const retBuf = Buffer.alloc(8);
    retBuf.writeBigInt64LE(BigInt(retVal));

    ctx.set("Content-Type", "application/octet-stream");
    ctx.set("Content-Length", (retBuf.length + content.length).toString());

    ctx.body = Buffer.concat([retBuf, content]);
}
