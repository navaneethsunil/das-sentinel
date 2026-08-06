/** Shown when a page's primary resource is forbidden for the signed-in role.
 * Says which roles may see it, so an analyst can tell "not for my role" from
 * "the app is broken" — the API refusal stays the enforcement. */
export function AccessDenied({ title, message }: { title: string; message: string }) {
  return (
    <div className="max-w-2xl space-y-2" data-testid="access-denied">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p role="alert" className="text-sm text-muted-foreground">
        {message}
      </p>
    </div>
  );
}
