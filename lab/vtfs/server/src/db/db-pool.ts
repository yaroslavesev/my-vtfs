
import {Pool} from "pg";
import appConfig from "@configs/app";

export const dbPool = new Pool({
    host: appConfig.DB_HOST,
    port: appConfig.PG_PORT,
    user: appConfig.POSTGRES_USER,
    password: appConfig.POSTGRES_PASSWORD,
    database: appConfig.POSTGRES_DB,
});
const connectToDB = async () => {
    try {
        await dbPool.connect();
    } catch (err) {
        console.error("connect db error", err);
    }
};
connectToDB();
