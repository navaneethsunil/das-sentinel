import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

import { Badge } from "@/components/ui/badge";
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
        <aside className="flex w-60 shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground">
          <div className="border-b px-5 py-4">
            <Link href="/" className="text-base font-semibold tracking-tight">
              DAS Sentinel
            </Link>
            <p className="mt-0.5 text-xs text-muted-foreground">Authorized testing only</p>
          </div>
          <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
            {sections.map((section) => (
              <div key={section.title}>
                <p className="px-2 pb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  {section.title}
                </p>
                <ul className="space-y-0.5">
                  {section.items.map((item) => (
                    <li key={item.label}>
                      {item.href ? (
                        <Link
                          href={item.href}
                          className="block rounded-md px-2 py-1.5 text-sm hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                        >
                          {item.label}
                        </Link>
                      ) : (
                        <span className="flex items-center justify-between rounded-md px-2 py-1.5 text-sm text-muted-foreground/60">
                          {item.label}
                          <Badge variant="outline" className="text-[10px]">
                            soon
                          </Badge>
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
          <UserMenu />
        </aside>
        <main className="min-w-0 flex-1 px-8 py-6">{children}</main>
      </body>
    </html>
  );
}
