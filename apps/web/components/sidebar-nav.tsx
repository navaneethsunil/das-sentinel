"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export type NavSection = {
  title: string;
  items: { label: string; href?: string }[];
};

function isActive(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}

export function SidebarNav({ sections }: { sections: NavSection[] }) {
  const pathname = usePathname();
  return (
    <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-5">
      {sections.map((section) => (
        <div key={section.title}>
          <p className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/70">
            {section.title}
          </p>
          <ul className="space-y-0.5">
            {section.items.map((item) => {
              const active = item.href ? isActive(pathname, item.href) : false;
              return (
                <li key={item.label}>
                  {item.href ? (
                    <Link
                      href={item.href}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "relative flex items-center rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                        active
                          ? "bg-sidebar-accent text-sidebar-accent-foreground"
                          : "text-sidebar-foreground/80 hover:bg-foreground/[0.04] hover:text-sidebar-foreground",
                      )}
                    >
                      {active && (
                        <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-sidebar-primary" />
                      )}
                      {item.label}
                    </Link>
                  ) : (
                    <span className="flex items-center justify-between rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground/45">
                      {item.label}
                      <Badge
                        variant="outline"
                        className="border-border/70 text-[9px] font-medium uppercase tracking-wide text-muted-foreground/60"
                      >
                        soon
                      </Badge>
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}
