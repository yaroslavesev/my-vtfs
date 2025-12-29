import Router from "@koa/router";
import apiRoutes from "./middlewares/router";

const router = new Router({
    prefix: '/api'
});

router.use(apiRoutes.routes());
router.use(apiRoutes.allowedMethods());

export default router;
