import type { Request, Response } from "express";

import { orders } from "../store";

export async function getOrder(request: Request, response: Response) {
  const orderId = request.params.orderId;
  const accountId = request.auth.accountId;
  const order = await orders.findForAccount(orderId, accountId);
  if (order === null) {
    return response.sendStatus(404);
  }
  return response.json(order);
}
