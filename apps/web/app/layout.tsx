import { ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import localFont from "next/font/local";
import Link from "next/link";
import "./globals.css";

import { AppBackground } from "@/components/app-background";
import { SidebarNav } from "@/components/sidebar-nav";
import { UserMenu } from "@/components/user-menu";
import { serverMe } from "@/lib/api/server";
import type { UserRole } from "@/lib/api/types";

// Self-hosted (vendored) font — air-gap safe, no build-time download. One
// standard, highly readable sans (Inter) for the whole app.
const fontSans = localFont({
  src: "./fonts/Inter-Variable.woff2",
  variable: "--font-inter",
  weight: "100 900",
  display: "swap",
});

export const metadata: Metadata = {
  title: "DAS Sentinel",
  description:
    "AI security testing and automated penetration-testing platform for authorized defensive security assessments.",
};

// Top-level nav: only real links. Targets/Scans/Findings/Reports are per-engagement
// (nothing exists outside a scoped engagement — §2.1), so they surface in the
// contextual "Current engagement" menu (SidebarNav) rather than as global entries.
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
    items: [{ label: "Engagements", href: "/engagements" }],
  },
  {
    title: "Credentials",
    // Managing secrets is an Admin/Tester action (MANAGE_CREDENTIALS); viewers
    // never see the vault. The API's RBAC guard is the real enforcement.
    items: [{ label: "Credentials", href: "/credentials", roles: ["admin", "tester"] }],
  },
  {
    title: "Administration",
    // User management is Admin-only (MANAGE_USERS); other roles never see it.
    // The API's RBAC guard is the real enforcement.
    items: [{ label: "Users", href: "/users", roles: ["admin"] }],
  },
  {
    title: "Output",
    items: [{ label: "Audit log", href: "/audit", roles: ["admin", "reviewer"] }],
  },
  {
    title: "System",
    items: [
      { label: "AI models", href: "/ai-models" },
      { label: "Health", href: "/health" },
    ],
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
    <html lang="en" className={`dark h-full antialiased ${fontSans.variable}`}>
      <body className="relative flex min-h-full font-sans">
        <AppBackground />
        <aside className="sticky top-0 flex h-dvh w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar/70 text-sidebar-foreground backdrop-blur-xl">
          <div className="px-5 py-5">
            <Link href="/" className="group flex items-center gap-2.5">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground shadow-sm">
                <ShieldCheck className="size-[18px]" aria-hidden />
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
          <div className="mx-auto max-w-6xl px-8 py-8 duration-500 animate-in fade-in slide-in-from-bottom-2">
            {children}
          </div>
        </main>
      </body>
    </html>
  );
}
