import { Knex } from 'knex';

/**
 * Base row type for mongoose collections
 */
export interface Model{
  /**
   * ID of the row
   */
  id: string;
  /**
   * date the row was created
   */
  created_at: Date;
  /**
   * date the row was updated
   */
  updated_at: Date | null;
  /**
   * date the row was deleted
   */
  deleted_at: Date | null;
}

export class Pagination<T> {
  docs: T[];
  total: number;
  totalPages: number;
  current: number;
  prev: number | null;
  next: number | null;

  constructor(
    docs: T[],
    total: number,
    current: number,
    limit: number,
  ) {
    this.docs = docs;
    this.total = total;
    this.totalPages = Math.ceil(total / limit);
    this.current = Number(current);
    this.prev = Number(current) > 1 ? Number(current) - 1 : null;
    this.next = Number(current) < this.totalPages ? Number(current) + 1 : null;
  }

  public static async createPaginatedResponse<T>(
    baseQuery: Knex.QueryBuilder,
    page: number = 1,
    limit: number = 10,
    sort: Record<string, 'asc' | 'desc'> = { id: 'asc' },
    countQuery: Knex.QueryBuilder = baseQuery.clone(),
  ): Promise<Pagination<T>> {
    const offset = (page - 1) * limit;

    const cQuery = countQuery.clearSelect().count(`* as count`).first();
    const dataQuery = baseQuery.clone()
      .orderBy(Object.entries(sort).map(([key, value]) => ({ column: key, order: value })))
      .offset(offset)
      .limit(limit);

    const [data, countResult] = await Promise.all([dataQuery, cQuery]);

    const total = Number(countResult?.count || 0);

    return new Pagination<T>(data, total, page, limit);
  }
}

