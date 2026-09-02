"use client";

import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";

const pad = (n: number) => String(n).padStart(2, "0");
const WEEKDAYS = ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"];
const MONTHS = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];

/** Date+time field with its own calendar popup (the native picker's popup is
 * browser chrome and can't hold an Apply button). Clicking the field opens the
 * calendar; pick a day, set the time, and Apply — inside the popup — commits
 * the value and closes. Clicking the field again reopens it to change.
 * `value` stays the "YYYY-MM-DDTHH:mm" local-input format ("" = unset). */
export function DateTimeField({
  id,
  label,
  value,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [draftDate, setDraftDate] = useState<string | null>(null); // "YYYY-MM-DD"
  const [draftTime, setDraftTime] = useState("09:00");
  const [viewYear, setViewYear] = useState(0);
  const [viewMonth, setViewMonth] = useState(0); // 0-based

  function openPicker() {
    const base = value ? new Date(value) : new Date();
    setDraftDate(value ? value.slice(0, 10) : null);
    setDraftTime(value ? value.slice(11, 16) : "09:00");
    setViewYear(base.getFullYear());
    setViewMonth(base.getMonth());
    setOpen(true);
  }

  function shiftMonth(delta: number) {
    const next = new Date(viewYear, viewMonth + delta, 1);
    setViewYear(next.getFullYear());
    setViewMonth(next.getMonth());
  }

  function apply() {
    if (draftDate) {
      onChange(`${draftDate}T${draftTime || "09:00"}`);
    }
    setOpen(false);
  }

  const firstWeekday = new Date(viewYear, viewMonth, 1).getDay();
  const daysInMonth = new Date(viewYear, viewMonth + 1, 0).getDate();
  const todayIso = (() => {
    const t = new Date();
    return `${t.getFullYear()}-${pad(t.getMonth() + 1)}-${pad(t.getDate())}`;
  })();

  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative">
        <button
          type="button"
          id={id}
          onClick={() => (open ? setOpen(false) : openPicker())}
          aria-haspopup="dialog"
          aria-expanded={open}
          className="border-input flex h-8 w-full items-center justify-between gap-2 rounded-lg border bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
        >
          <span className={value ? "" : "text-muted-foreground"}>
            {value ? new Date(value).toLocaleString() : "Pick date & time"}
          </span>
          {/* calendar glyph */}
          <svg
            aria-hidden
            viewBox="0 0 16 16"
            className="size-3.5 shrink-0 text-muted-foreground"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
          >
            <rect x="1.5" y="2.5" width="13" height="12" rx="2" />
            <path d="M1.5 6h13M5 1v3M11 1v3" />
          </svg>
        </button>
        {open && (
          <>
            {/* Click-away backdrop — same pattern as the account menu. */}
            <button
              type="button"
              aria-hidden
              tabIndex={-1}
              className="fixed inset-0 z-40 cursor-default"
              onClick={() => setOpen(false)}
            />
            <div
              role="dialog"
              aria-label={`${label} picker`}
              data-month={`${viewYear}-${pad(viewMonth + 1)}`}
              className="absolute left-0 z-50 mt-2 w-72 space-y-2 rounded-xl border bg-popover p-3 text-popover-foreground shadow-lg"
            >
              <div className="flex items-center justify-between">
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  aria-label="Previous month"
                  onClick={() => shiftMonth(-1)}
                >
                  ‹
                </Button>
                <span className="text-sm font-medium">
                  {MONTHS[viewMonth]} {viewYear}
                </span>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  aria-label="Next month"
                  onClick={() => shiftMonth(1)}
                >
                  ›
                </Button>
              </div>
              <div className="grid grid-cols-7 gap-0.5 text-center text-xs">
                {WEEKDAYS.map((day) => (
                  <span key={day} className="py-1 text-muted-foreground">
                    {day}
                  </span>
                ))}
                {Array.from({ length: firstWeekday }, (_, i) => (
                  <span key={`blank-${i}`} />
                ))}
                {Array.from({ length: daysInMonth }, (_, i) => {
                  const iso = `${viewYear}-${pad(viewMonth + 1)}-${pad(i + 1)}`;
                  const selected = iso === draftDate;
                  return (
                    <button
                      key={iso}
                      type="button"
                      aria-label={iso}
                      onClick={() => setDraftDate(iso)}
                      className={
                        "rounded-md py-1 tabular-nums outline-none focus-visible:ring-2 focus-visible:ring-ring/50 " +
                        (selected
                          ? "bg-primary font-semibold text-primary-foreground"
                          : "hover:bg-muted " +
                            (iso === todayIso ? "font-semibold text-primary" : ""))
                      }
                    >
                      {i + 1}
                    </button>
                  );
                })}
              </div>
              <div className="flex items-center gap-2 border-t pt-2">
                <Label htmlFor={`${id}-time`} className="text-xs text-muted-foreground">
                  Time
                </Label>
                <input
                  id={`${id}-time`}
                  type="time"
                  value={draftTime}
                  onChange={(e) => setDraftTime(e.target.value)}
                  className="border-input h-7 flex-1 rounded-md border bg-transparent px-2 text-sm outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/50"
                />
              </div>
              <div className="flex gap-2">
                <Button
                  type="button"
                  size="sm"
                  className="flex-1"
                  disabled={!draftDate}
                  onClick={apply}
                >
                  Apply
                </Button>
                {value && (
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    onClick={() => {
                      onChange("");
                      setOpen(false);
                    }}
                  >
                    Clear
                  </Button>
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
