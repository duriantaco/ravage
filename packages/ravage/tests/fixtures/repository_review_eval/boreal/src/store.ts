export interface OrderRecord {
  readonly id: string;
  readonly accountId: string;
  readonly totalCents: number;
}

const records: readonly OrderRecord[] = [
  { id: "order-100", accountId: "account-a", totalCents: 1250 },
  { id: "order-200", accountId: "account-b", totalCents: 2500 },
];

export const orders = {
  async findById(orderId: string): Promise<OrderRecord | null> {
    return records.find((order) => order.id === orderId) ?? null;
  },

  async findForAccount(orderId: string, accountId: string): Promise<OrderRecord | null> {
    return (
      records.find((order) => order.id === orderId && order.accountId === accountId) ?? null
    );
  },
};
