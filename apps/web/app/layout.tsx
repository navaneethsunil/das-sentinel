import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

import { SidebarNav } from "@/components/sidebar-nav";
import { UserMenu } from "@/components/user-menu";
import { serverMe } from "@/lib/api/server";
import type { UserRole } from "@/lib/api/types";

export const metadata: Metadata = {
  title: "DAS Sentinel",
  description:
    "AI security testing and automated penetration-testing platform for authorized defensive security assessments.",
};

// Nav lands milestone by milestone (M1 engagements/targets, M2 AI test suites,
// M3 scans/findings). Unbuilt entries render disabled ("soon") — no dead links.
// `roles` gates an item to those roles (M1-F5); omitted = every signed-in role.
// Gating here is convenience only — the API's RBAC guards are the enforcement.
const NAV_SECTIONS: {
  title: string;
  items: { label: string; href?: string; roles?: UserRole[] }[];
}[] = [
  {
    title: "Overview",
    items: [{ label: "Dashboard", href: "/" }],
  },
  {
    title: "Testing",
    items: [
      { label: "Engagements", href: "/engagements" },
      { label: "Targets" },
      { label: "Scans" },
      { label: "Findings" },
    ],
  },
  {
    title: "Output",
    items: [
      { label: "Reports" },
      { label: "Audit log", href: "/audit", roles: ["admin", "reviewer"] },
    ],
  },
  {
    title: "System",
    items: [{ label: "Health", href: "/health" }],
  },
];

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const me = await serverMe();
  const sections = NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter(
      (item) => !item.roles || (me !== null && item.roles.includes(me.role)),
    ),
  }));
  return (
    <html lang="en" className="h-full antialiased">
      <body className="flex min-h-full font-sans">
        <aside className="flex w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground">
          <div className="px-5 py-5">
            <Link href="/" className="group flex items-center gap-2.5">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-sidebar-primary font-semibold text-sidebar-primary-foreground shadow-sm">
                S
              </span>
              <span className="flex flex-col leading-none">
                <span className="text-[15px] font-semibold tracking-tight">DAS Sentinel</span>
                <span className="mt-1 text-[11px] font-medium text-muted-foreground">
                  Authorized testing only
                </span>
              </span>
            </Link>
          </div>
          <SidebarNav sections={sections} />
          <UserMenu />
        </aside>
        <main className="min-w-0 flex-1">
          <div className="mx-auto max-w-6xl px-8 py-8">{children}</div>
        </main>
      </body>
    </html>
  );
}
