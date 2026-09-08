import type { Request, Response } from "express";

import { orders } from "../store";

export async function getOrder(request: Request, response: Response) {
  const orderId = request.params.orderId;
  const order = await orders.findById(orderId);
  if (order === null) {
    return response.sendStatus(404);
  }
  return response.json(order);
}
