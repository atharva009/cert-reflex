import { useCallback, useEffect, useRef, useState } from 'react';
import ListenerPanel from './components/ListenerPanel.jsx';
import EventLog from './components/EventLog.jsx';

const POLL_INTERVAL_MS = 1000;
const TICK_INTERVAL_MS = 250;
const EVENT_LIMIT = 50;

/**
 * Owns the polling state; panels and the log are given props.
 *
 * The dashboard is meant to be an independent witness to what the backend
 * says. It never guesses: a failure-injection click is not applied optimistically,
 * and a failed poll keeps the last good data on screen rather than blanking it.
 */
export default function Dashboard() {
  const [certs, setCerts] = useState([]);
  const [events, setEvents] = useState([]);
  // performance.now() when the current cert data arrived, so the countdown can
  // be decremented locally without doing clock arithmetic against the server.
  const [syncedAt, setSyncedAt] = useState(null);
  const [lastSuccessAt, setLastSuccessAt] = useState(null);
  const [stale, setStale] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [, setTick] = useState(0);

  const poll = useCallback(async () => {
    try {
      const [certsResponse, eventsResponse] = await Promise.all([
        fetch('/internal/certs'),
        fetch('/internal/events'),
      ]);
      if (!certsResponse.ok || !eventsResponse.ok) {
        throw new Error(`HTTP ${certsResponse.status}/${eventsResponse.status}`);
      }
      const [nextCerts, nextEvents] = await Promise.all([
        certsResponse.json(),
        eventsResponse.json(),
      ]);
      setCerts(nextCerts);
      setEvents(nextEvents.slice(-EVENT_LIMIT));
      setSyncedAt(performance.now());
      setLastSuccessAt(Date.now());
      setStale(false);
      setLoaded(true);
    } catch {
      // Keep whatever is on screen. A blank dashboard while the backend is
      // merely restarting is the worst thing this could do during a demo.
      setStale(true);
    }
  }, []);

  useEffect(() => {
    poll();
    const id = setInterval(poll, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [poll]);

  // Repaint faster than the poll so the countdown decrements once a second on
  // its own rather than lurching whenever a response happens to land.
  useEffect(() => {
    const id = setInterval(() => setTick((value) => value + 1), TICK_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  const injectFailure = useCallback(async (serviceName, type) => {
    try {
      await fetch(`/internal/failures/${serviceName}?type=${type}`, { method: 'POST' });
    } catch {
      setStale(true);
    }
    // Deliberately no optimistic update: the next poll reports whatever the
    // backend actually did, including the lag before the watcher notices.
  }, []);

  const elapsedSeconds = syncedAt === null ? 0 : Math.floor((performance.now() - syncedAt) / 1000);
  const staleForSeconds = lastSuccessAt === null ? null : Math.floor((Date.now() - lastSuccessAt) / 1000);

  return (
    <main>
      <h1>Cert-Reflex</h1>

      {stale && (
        <p role="status" data-testid="stale-banner">
          Connection to the backend lost
          {staleForSeconds !== null && ` ${staleForSeconds}s ago`}. Showing the last known state.
        </p>
      )}

      {!loaded && !stale && <p>Loading…</p>}

      <section>
        {certs.map((cert) => (
          <ListenerPanel
            key={cert.serviceName}
            cert={cert}
            // The server's value is authoritative; only the elapsed time since
            // it arrived is measured here.
            secondsRemaining={cert.secondsUntilExpiry - elapsedSeconds}
            stale={stale}
            onInject={injectFailure}
          />
        ))}
      </section>

      <EventLog events={events} />
    </main>
  );
}
