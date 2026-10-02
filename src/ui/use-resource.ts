import { useCallback, useEffect, useState } from "react";
import { ApiError } from "./api";

export function useResource<T>(
  load: () => Promise<T>,
  onUnauthorized: () => void,
  dependencies: readonly unknown[] = [],
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshIndex, setRefreshIndex] = useState(0);

  const refresh = useCallback(() => setRefreshIndex((value) => value + 1), []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    void load()
      .then((value) => {
        if (active) setData(value);
      })
      .catch((cause: unknown) => {
        if (!active) return;
        if (cause instanceof ApiError && cause.status === 401) {
          onUnauthorized();
          return;
        }
        setError(cause instanceof Error ? cause.message : "The data could not be loaded.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
    // Callers pass stable loaders or primitive dependencies deliberately.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...dependencies, refreshIndex]);

  return { data, setData, error, setError, loading, refresh };
}
