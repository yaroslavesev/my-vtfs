import Koa from 'koa';
import json from 'koa-json';
import bodyParser from 'koa-bodyparser';
import catchErrors from '@api/middlewares/catch-errors';
import appConfig from '@configs/app'
import apiRouter from "@api";

const app = new Koa();

app.use(catchErrors);
app.use(json());
app.use(bodyParser());

app.use(apiRouter.routes());
app.use(apiRouter.allowedMethods());

app.listen(appConfig.port, "0.0.0.0",() => {
    console.log(`🚀 Server listening on port ${appConfig.port}`);
});
