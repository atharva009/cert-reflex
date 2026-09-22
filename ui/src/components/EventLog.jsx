import { useEffect, useRef } from 'react';

/**
 * The event feed: one line per event, newest at the bottom, following the tail.
 *
 * The event type is rendered as whatever string the API sent. The enum has
 * already grown once (INJECTED) and may again, so nothing here looks a type up
 * in a table that could miss and break the feed.
 */
export default function EventLog({ events }) {
  const bottom = useRef(null);

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'nearest' });
  }, [events.length]);

  return (
    <section className="log">
      <h2>Event log</h2>
      <ol data-testid="event-log">
        {events.map((event) => (
          <li key={event.id} data-event-type={event.eventType}>
            <time className="at" dateTime={event.createdAt}>{formatTime(event.createdAt)}</time>
            <span className="who">{event.serviceName}</span>
            <span className="what">{sentenceCase(event.eventType)}</span>
            <span className="message">{event.message}</span>
          </li>
        ))}
        <li ref={bottom} aria-hidden="true" />
      </ol>
    </section>
  );
}

function formatTime(iso) {
  // Defensive: the feed should render even if a timestamp is not what we expect.
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime())
    ? iso
    : parsed.toLocaleTimeString([], { hour12: false });
}

/** DETECTED_EXPIRING -> "Detected expiring"; unknown types pass through the same way. */
function sentenceCase(eventType) {
  const words = String(eventType).toLowerCase().replaceAll('_', ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}
