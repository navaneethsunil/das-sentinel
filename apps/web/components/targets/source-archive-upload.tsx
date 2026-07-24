"use client";

import { useRouter } from "next/navigation";
import { useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { ApiError, uploadSourceArchive } from "@/lib/api/client";
import type { SourceArchiveUploadResult } from "@/lib/api/types";

/** Upload a source archive (zip/tar) to a source_archive target (M3-B1). The
 * archive is stored as content-addressed evidence and the target's primary_value
 * is repointed at its object key so the SAST scanner can materialize it. */
export function SourceArchiveUpload({
  engagementId,
  targetId,
}: {
  engagementId: string;
  targetId: string;
}) {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<SourceArchiveUploadResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);

  async function onUpload(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setResult(null);
    if (!file) {
      setError("Choose an archive (.zip or .tar) to upload.");
      return;
    }
    setUploading(true);
    try {
      const uploaded = await uploadSourceArchive(engagementId, targetId, file);
      setResult(uploaded);
      setFile(null);
      if (inputRef.current) {
        inputRef.current.value = "";
      }
      router.refresh(); // reflect the updated primary_value
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 413) {
        setError("That archive is too large.");
      } else if (caught instanceof ApiError && caught.status === 422) {
        setError(caught.detail ?? "That file is not a valid, safe archive.");
      } else {
        setError("Upload failed — try again.");
      }
    } finally {
      setUploading(false);
    }
  }

  return (
    <form onSubmit={onUpload} className="space-y-3" noValidate data-testid="source-archive-upload">
      <input
        ref={inputRef}
        type="file"
        accept=".zip,.tar,.tar.gz,.tgz,application/zip,application/x-tar,application/gzip"
        className="block w-full text-sm file:mr-3 file:rounded-lg file:border file:border-input file:bg-transparent file:px-3 file:py-1.5 file:text-sm"
        onChange={(e) => setFile(e.target.files?.[0] ?? null)}
      />
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {result && (
        <p className="text-sm text-emerald-600" data-testid="upload-result">
          Uploaded {result.archive_format} archive ({result.size_bytes} bytes) — sha256{" "}
          <code className="text-xs">{result.content_sha256.slice(0, 16)}…</code>
        </p>
      )}
      <Button type="submit" disabled={uploading || !file}>
        {uploading ? "Uploading…" : "Upload archive"}
      </Button>
    </form>
  );
}
