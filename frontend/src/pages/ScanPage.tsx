import { ArrowLeft } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import VerdictView from "../components/VerdictView";
import { ChannelTag, ErrorNote, Spinner } from "../components/ui";
import { api } from "../lib/api";
import type { Verdict } from "../lib/types";

export default function ScanPage() {
  const { id = "" } = useParams();
  const [scan, setScan] = useState<Verdict | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setScan(null);
    setError(null);
    api.getScan(id).then(setScan, (e: Error) => setError(e.message));
  }, [id]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <Link to="/history" className="inline-flex min-h-10 items-center gap-1.5 text-sm font-medium text-ink-2 hover:text-ink">
          <ArrowLeft className="size-4" aria-hidden /> History
        </Link>
        {scan && <ChannelTag channel={scan.channel} />}
      </div>
      {error && <ErrorNote message={error} />}
      {!scan && !error && <div className="flex justify-center py-16 text-ink-3"><Spinner /></div>}
      {scan && <VerdictView key={scan.scan_id} verdict={scan} />}
    </div>
  );
}
