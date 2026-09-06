export function orderLabel(reference: string): string {
  return `Order ${reference.replaceAll("<", "&lt;")}`;
}
