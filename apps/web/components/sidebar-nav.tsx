"use client";

import {
  Activity,
  Bot,
  Bug,
  BadgeCheck,
  Crosshair,
  FileText,
  KeyRound,
  LayoutDashboard,
  PanelsTopLeft,
  Radar,
  ScrollText,
  ShieldCheck,
  Users,
  type LucideIcon,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { MouseEvent } from "react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export type NavSection = {
  title: string;
  items: { label: string; href?: string }[];
};

type RenderItem = { label: string; href?: string; active?: boolean };

// Keyed by label so the (server-rendered) sections stay plain-serializable data.
const ICONS: Record<string, LucideIcon> = {
  Dashboard: LayoutDashboard,
  Engagements: ShieldCheck,
  Credentials: KeyRound,
  Users: Users,
  Overview: PanelsTopLeft,
  Targets: Crosshair,
  Scans: Radar,
  Findings: Bug,
  Reports: FileText,
  "Audit log": ScrollText,
  Approvals: BadgeCheck,
  "AI models": Bot,
  Health: Activity,
};

const ENGAGEMENT_RE = /\/engagements\/([0-9a-f-]{36})/;

function isActive(pathname: string, href: string): boolean {
  const path = href.split("#")[0];
  return path === "/" ? pathname === "/" : pathname === path || pathname.startsWith(`${path}/`);
}

function NavItem({ item }: { item: RenderItem }) {
  const pathname = usePathname();
  const Icon = ICONS[item.label];
  if (!item.href) {
    return (
      <span className="flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground/45">
        {Icon && <Icon className="size-4 shrink-0 text-muted-foreground/40" aria-hidden />}
        <span className="flex-1">{item.label}</span>
        <Badge
          variant="outline"
          className="border-border/70 text-[9px] font-medium uppercase tracking-wide text-muted-foreground/60"
        >
          soon
        </Badge>
      </span>
    );
  }
  const active = item.active ?? false;
  // Same-page hash link (e.g. #targets on the engagement overview): the browser
  // no-ops when the hash already matches, so scrolling away then clicking again
  // does nothing. Intercept and scroll manually so every click re-scrolls.
  const [path, hash] = item.href.split("#");
  const scrollToAnchor =
    hash && path === pathname
      ? (event: MouseEvent<HTMLAnchorElement>) => {
          const target = document.getElementById(hash);
          if (target) {
            event.preventDefault();
            target.scrollIntoView({ behavior: "smooth", block: "start" });
            window.history.replaceState(null, "", item.href);
          }
        }
      : undefined;
  return (
    <Link
      href={item.href}
      onClick={scrollToAnchor}
      aria-current={active ? "page" : undefined}
      className={cn(
        "relative flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
        active
          ? "bg-sidebar-accent text-sidebar-accent-foreground"
          : "text-sidebar-foreground/80 hover:bg-foreground/[0.04] hover:text-sidebar-foreground",
      )}
    >
      {active && (
        <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-sidebar-primary" />
      )}
      {Icon && (
        <Icon
          className={cn(
            "size-4 shrink-0",
            active ? "text-sidebar-primary" : "text-muted-foreground",
          )}
          aria-hidden
        />
      )}
      {item.label}
    </Link>
  );
}

function Section({ title, items }: { title: string; items: RenderItem[] }) {
  return (
    <div>
      <p className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/70">
        {title}
      </p>
      <ul className="space-y-0.5">
        {items.map((item) => (
          <li key={item.label}>
            <NavItem item={item} />
          </li>
        ))}
      </ul>
    </div>
  );
}

export function SidebarNav({ sections }: { sections: NavSection[] }) {
  const pathname = usePathname();
  const eid = pathname.match(ENGAGEMENT_RE)?.[1];
  const base = eid ? `/engagements/${eid}` : "";

  // In-engagement contextual nav: the scoped Targets/Scans/Findings/Reports the
  // global "soon" items stand in for. Targets/Scans are cards on the overview
  // page (hash anchors); Findings/Reports have their own routes.
  const engagementItems: RenderItem[] = eid
    ? [
        { label: "Overview", href: base, active: pathname === base },
        { label: "Targets", href: `${base}#targets` },
        { label: "Scans", href: `${base}#scans` },
        {
          label: "Findings",
          href: `${base}/findings`,
          active: pathname.startsWith(`${base}/findings`),
        },
        {
          label: "Reports",
          href: `${base}/reports`,
          active: pathname.startsWith(`${base}/reports`),
        },
        {
          label: "Approvals",
          href: `${base}/approvals`,
          active: pathname.startsWith(`${base}/approvals`),
        },
      ]
    : [];

  return (
    <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-5">
      {sections.map((section) => (
        <Section
          key={section.title}
          title={section.title}
          items={section.items.map((item) => ({
            ...item,
            active: item.href ? isActive(pathname, item.href) : false,
          }))}
        />
      ))}
      {eid && <Section title="Current engagement" items={engagementItems} />}
    </nav>
  );
}
