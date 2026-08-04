"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, changeMyPassword, updateMe } from "@/lib/api/client";
import type { User } from "@/lib/api/types";

/** Self-service account settings: profile (name/email/phone) and password.
 * The API's PATCH /auth/me and POST /auth/me/password are the enforcement. */
export function ProfileForm({ user }: { user: User }) {
  const router = useRouter();

  const [displayName, setDisplayName] = useState(user.display_name);
  const [email, setEmail] = useState(user.email);
  const [phone, setPhone] = useState(user.phone ?? "");
  const [profileMsg, setProfileMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [savingProfile, setSavingProfile] = useState(false);

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pwMsg, setPwMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [savingPw, setSavingPw] = useState(false);

  async function onSaveProfile(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setProfileMsg(null);
    setSavingProfile(true);
    try {
      // A PATCH sends only what changed — resubmitting an untouched email would
      // make every profile save re-write a unique-constrained column.
      const nextPhone = phone.trim() || null;
      const changed: Parameters<typeof updateMe>[0] = {};
      if (displayName !== user.display_name) changed.display_name = displayName;
      if (email !== user.email) changed.email = email;
      if (nextPhone !== (user.phone ?? null)) changed.phone = nextPhone;
      await updateMe(changed);
      setProfileMsg({ ok: true, text: "Profile saved." });
      router.refresh();
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 409) {
        setProfileMsg({ ok: false, text: "That email is already in use." });
      } else {
        setProfileMsg({ ok: false, text: "Saving your profile failed — try again." });
      }
    } finally {
      setSavingProfile(false);
    }
  }

  async function onChangePassword(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPwMsg(null);
    if (next.length < 12) {
      setPwMsg({ ok: false, text: "New password must be at least 12 characters." });
      return;
    }
    if (next !== confirm) {
      setPwMsg({ ok: false, text: "New passwords do not match." });
      return;
    }
    setSavingPw(true);
    try {
      await changeMyPassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setPwMsg({ ok: true, text: "Password changed." });
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 400) {
        setPwMsg({ ok: false, text: "Current password is incorrect." });
      } else if (caught instanceof ApiError && caught.status === 422) {
        setPwMsg({ ok: false, text: caught.detail ?? "Choose a different password." });
      } else {
        setPwMsg({ ok: false, text: "Changing your password failed — try again." });
      }
    } finally {
      setSavingPw(false);
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Profile</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSaveProfile} className="space-y-3" noValidate>
            <div className="space-y-1.5">
              <Label htmlFor="display_name">Name</Label>
              <Input
                id="display_name"
                required
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="phone">Phone number</Label>
              <Input
                id="phone"
                type="tel"
                placeholder="optional"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
              />
            </div>
            {profileMsg && (
              <p
                role={profileMsg.ok ? "status" : "alert"}
                className={profileMsg.ok ? "text-sm text-emerald-400" : "text-sm text-destructive"}
              >
                {profileMsg.text}
              </p>
            )}
            <Button type="submit" size="sm" disabled={savingProfile}>
              {savingProfile ? "Saving…" : "Save profile"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Password</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onChangePassword} className="space-y-3" noValidate>
            <div className="space-y-1.5">
              <Label htmlFor="current_password">Current password</Label>
              <Input
                id="current_password"
                type="password"
                autoComplete="current-password"
                required
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="next_password">New password</Label>
              <Input
                id="next_password"
                type="password"
                autoComplete="new-password"
                required
                placeholder="at least 12 characters"
                value={next}
                onChange={(e) => setNext(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="confirm_password">Confirm new password</Label>
              <Input
                id="confirm_password"
                type="password"
                autoComplete="new-password"
                required
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
              />
            </div>
            {pwMsg && (
              <p
                role={pwMsg.ok ? "status" : "alert"}
                className={pwMsg.ok ? "text-sm text-emerald-400" : "text-sm text-destructive"}
              >
                {pwMsg.text}
              </p>
            )}
            <Button type="submit" size="sm" disabled={savingPw}>
              {savingPw ? "Saving…" : "Change password"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
