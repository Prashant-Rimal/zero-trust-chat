import { useCallback, useEffect, useState } from 'react'
import { api, useApp } from './session'

/** Loads an API resource and reloads it whenever the server signals a change over the socket. */
export function useRemote<T>(path: string) {
  const { remote } = useApp()
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const reload = useCallback(async () => {
    try {
      setData(await api<T>('GET', path))
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    }
  }, [path])
  useEffect(() => {
    void reload()
  }, [reload, remote])
  return { data, error, reload }
}
