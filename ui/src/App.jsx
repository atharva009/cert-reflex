import { useCallback, useEffect, useRef, useState } from 'react';
import ListenerPanel from './components/ListenerPanel.jsx';
import EventLog from './components/EventLog.jsx';

const POLL_INTERVAL_MS = 1000;
const TICK_INTERVAL_MS = 250;
const EVENT_LIMIT = 50;
/**
 * How long a panel holds the rotating colour after a rotation completes.
 *
 * ROTATING itself lasts 60-100ms on the server, so a one-second poll never
 * catches it. What a poll can see is the transition out of EXPIRING or
 * CORRUPTED into ACTIVE, which means a rotation just finished. Holding the
 * blue on that edge renders something that genuinely happened rather than
 * inventing state or slowing the remediator down. The panel says "just
 * rotated", not "rotating", because that is what it knows.
 */
const JUST_ROTATED_MS = 800;

const PRE_ROTATION_STATUSES = new Set(['EXPIRING', 'CORRUPTED']);

/**
 * Owns the polling state; panels and the log are given props.
 *
 * The dashboard is an independent witness to what the backend says. It never
 * guesses: a failure-injection click is not applied optimistically, and a
 * failed poll keeps the last good data on screen rather than blanking it.
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

  const previousStatuses = useRef({});
  const justRotatedUntil = useRef({});

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

      for (const cert of nextCerts) {
        const previous = previousStatuses.current[cert.serviceName];
        if (cert.status === 'ACTIVE' && PRE_ROTATION_STATUSES.has(previous)) {
          justRotatedUntil.current[cert.serviceName] = performance.now() + JUST_ROTATED_MS;
        }
        previousStatuses.current[cert.serviceName] = cert.status;
      }

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
  // its own, and so the just-rotated hold expires on time.
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
    <main className="console">
      <header className="masthead">
        <h1>Cert-Reflex</h1>
        <span className="subtitle">
          Certificates detect their own expiry and corruption, and rotate without dropping connections.
        </span>
      </header>

      {stale && (
        <p className="notice" role="status" data-testid="stale-banner">
          Not reaching the backend
          {staleForSeconds !== null && ` (${staleForSeconds}s)`}. Showing the last state it reported.
        </p>
      )}
      {!loaded && !stale && (
        <p className="notice" role="status">Connecting to the backend.</p>
      )}

      <section className="panels">
        {certs.map((cert) => (
          <ListenerPanel
            key={cert.serviceName}
            cert={cert}
            // The server's value is authoritative; only the elapsed time since
            // it arrived is measured here.
            secondsRemaining={cert.secondsUntilExpiry - elapsedSeconds}
            justRotated={(justRotatedUntil.current[cert.serviceName] ?? 0) > performance.now()}
            stale={stale}
            onInject={injectFailure}
          />
        ))}
      </section>

      <EventLog events={events} />
    </main>
  );
}
