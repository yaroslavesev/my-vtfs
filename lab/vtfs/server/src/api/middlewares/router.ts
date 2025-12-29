import Router from "@koa/router";
import {list} from "@api/middlewares/cruds/list";
import {read} from "@api/middlewares/cruds/read";
import {mkdir} from "@api/middlewares/cruds/mkdir";
import {write} from "@api/middlewares/cruds/write";
import {create} from "@api/middlewares/cruds/create";
import {unlink} from "@api/middlewares/cruds/unlink";

const router = new Router();
router.get("/list", list)
router.get("/read", read)
router.get("/create", create)
router.get("/write", write)
router.get("/mkdir", mkdir)
router.get("/unlink", unlink)

export default router;