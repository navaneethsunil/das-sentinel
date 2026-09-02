"use client";

import { useMemo, useState } from "react";

/** Compact date+time for table cells; "—" for never. */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) {
    return "—";
  }
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export interface DataColumn<T> {
  key: string;
  label: string;
  /** Filter (and default sort/display) text for the cell. */
  value: (row: T) => string | number;
  /** Overrides `value` for ordering — return a number (e.g. Date.parse) for
   * numeric order when `value` is display text. */
  sortValue?: (row: T) => string | number;
  /** Cell renderer; defaults to the value as text. */
  render?: (row: T) => React.ReactNode;
  className?: string;
}

/** Sortable + filterable record list (ServiceNow-style): click a header to sort
 * asc → desc → off; the row of inputs under the headers filters per column
 * (case-insensitive substring). Purely client-side over the rows given. */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  testId,
  rowTestId,
}: {
  columns: DataColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  testId?: string;
  rowTestId?: string;
}) {
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const [filters, setFilters] = useState<Record<string, string>>({});

  function onHeaderClick(key: string) {
    setSort((current) => {
      if (current?.key !== key) return { key, dir: 1 };
      return current.dir === 1 ? { key, dir: -1 } : null;
    });
  }

  const visible = useMemo(() => {
    let out = rows.filter((row) =>
      columns.every((column) => {
        const query = filters[column.key]?.trim().toLowerCase();
        if (!query) return true;
        return String(column.value(row)).toLowerCase().includes(query);
      }),
    );
    const sortColumn = sort && columns.find((c) => c.key === sort.key);
    if (sort && sortColumn) {
      const order = sortColumn.sortValue ?? sortColumn.value;
      out = [...out].sort((a, b) => {
        const va = order(a);
        const vb = order(b);
        if (typeof va === "number" && typeof vb === "number") return (va - vb) * sort.dir;
        return String(va).localeCompare(String(vb), undefined, { sensitivity: "base" }) * sort.dir;
      });
    }
    return out;
  }, [rows, columns, filters, sort]);

  const hasFilter = Object.values(filters).some((f) => f.trim());

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm" data-testid={testId}>
      <thead>
        <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
          {columns.map((column) => (
            <th key={column.key} className="py-2 pr-4 font-medium last:pr-0">
              <button
                type="button"
                onClick={() => onHeaderClick(column.key)}
                aria-label={`Sort by ${column.label}`}
                className="inline-flex items-center gap-1 uppercase tracking-wider outline-none hover:text-foreground focus-visible:text-foreground"
              >
                {column.label}
                <span aria-hidden className="w-3 text-[10px]">
                  {sort?.key === column.key ? (sort.dir === 1 ? "▲" : "▼") : ""}
                </span>
              </button>
            </th>
          ))}
        </tr>
        <tr className="border-b">
          {columns.map((column) => (
            <th key={column.key} className="py-1.5 pr-4 font-normal last:pr-0">
              <input
                type="search"
                aria-label={`Filter ${column.label}`}
                placeholder="Search"
                value={filters[column.key] ?? ""}
                onChange={(e) =>
                  setFilters((current) => ({ ...current, [column.key]: e.target.value }))
                }
                className="border-input h-7 w-full min-w-16 rounded-md border bg-transparent px-2 text-xs font-normal outline-none placeholder:text-muted-foreground/60 focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/50"
              />
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {visible.length === 0 ? (
          <tr>
            <td colSpan={columns.length} className="py-6 text-center text-muted-foreground">
              {hasFilter ? "No records match the filters." : "No records."}
            </td>
          </tr>
        ) : (
          visible.map((row) => (
            <tr
              key={rowKey(row)}
              className="border-b align-top last:border-0 hover:bg-muted/50"
              data-testid={rowTestId}
            >
              {columns.map((column) => (
                <td key={column.key} className={column.className ?? "py-2.5 pr-4 last:pr-0"}>
                  {column.render ? column.render(row) : String(column.value(row))}
                </td>
              ))}
            </tr>
          ))
        )}
      </tbody>
      </table>
    </div>
  );
}
