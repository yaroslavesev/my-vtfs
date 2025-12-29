import {Context, Next} from "koa";
import {repository} from "@models/repository";

export async function list(ctx: Context, next: Next) {
    const token = String(ctx.query.token);
    const parentIno = parseInt(ctx.query.parent_ino as string, 10) || 0;

    console.log("[list] Incoming request:", { token, parentIno});

    const files = await repository.findByParent(parentIno, token);

    ctx.body = files.map(f => ({ ino: f.ino, name: f.name, is_dir: f.is_dir }));

    console.log("[list] Sending response:", files.map(f => ({ ino: f.ino, name: f.name, is_dir: f.is_dir })));
    await next();
}