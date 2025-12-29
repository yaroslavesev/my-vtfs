import { dbPool } from "../db/db-pool";
import {FileLab4} from "@models/file";


class Repository {
    tableName = "files";

    async findByParent(parent_ino: number, token: string): Promise<FileLab4[]> {
        const res = await dbPool.query(
            `SELECT * FROM ${this.tableName} WHERE parent_ino=$1 AND token=$2`,
            [parent_ino, token]
        );
        return res.rows.map(row => ({
            ...row,
            data: row.data ? Buffer.from(row.data) : null
        }));
    }

    async findByIno(ino: number, token: string): Promise<FileLab4 | null> {
        const res = await dbPool.query(
            `SELECT * FROM ${this.tableName} WHERE ino=$1 AND token=$2`,
            [ino, token]
        );
        if (!res.rows[0]) return null;
        const row = res.rows[0];
        return { ...row, data: row.data ? Buffer.from(row.data) : null };
    }

    async create(token: string, parent_ino: number, is_dir: boolean, data: Buffer | null, name: string): Promise<FileLab4> {
        const res = await dbPool.query(
            `INSERT INTO ${this.tableName} (token, parent_ino, is_dir, data, name) 
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [token, parent_ino, is_dir, data, name]
        );
        const row = res.rows[0];
        return { ...row, data: row.data ? Buffer.from(row.data) : null };
    }

    async update(ino: number, token: string, data: Partial<Omit<FileLab4, "ino">>): Promise<FileLab4 | null> {
        const keys = Object.keys(data);
        const values = Object.values(data);
        //console.log(values)
        if (!keys.length) return this.findByIno(ino, token);
        const setString = keys.map((k, i) => `${k}=$${i+1}`).join(", ");
        const res = await dbPool.query(
            `UPDATE ${this.tableName} SET ${setString} WHERE ino=$${keys.length+1} AND token=$${keys.length+2} RETURNING *`,
            [...values, ino, token]
        );
        if (!res.rows[0]) return null;
        const row = res.rows[0];
        return { ...row, data: row.data ? Buffer.from(row.data) : null };
    }

    async delete(ino: number, token: string): Promise<boolean> {
        const res = await dbPool.query(
            `DELETE FROM ${this.tableName} WHERE ino=$1 AND token=$2`,
            [ino, token]
        );
        return Boolean(res.rowCount && res.rowCount > 0 );
    }
}

export const repository = new Repository();
