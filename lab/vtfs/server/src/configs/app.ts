const appConfig = {
    port: Number(process.env.APP_PORT) || 8089,
    DB_HOST: process.env.DB_HOST || "localhost",
    PG_PORT: Number(process.env.DB_PORT) || 5432,
    POSTGRES_USER: process.env.DB_USER || "s408145",
    POSTGRES_PASSWORD: process.env.DB_PASS || "JLzD%6772",
    POSTGRES_DB: process.env.DB_NAME || "studs",
}


export default appConfig;
