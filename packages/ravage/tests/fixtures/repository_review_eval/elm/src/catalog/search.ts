import type { Request, Response } from "express";

import { database } from "../database";

export async function searchCatalog(request: Request, response: Response) {
  const term = String(request.query.term ?? "");
  const rows = await database.all(
    `SELECT sku, title FROM catalog WHERE title LIKE '%${term}%'`
  );
  return response.json(rows);
}
