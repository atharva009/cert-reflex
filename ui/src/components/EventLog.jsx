import { useEffect, useRef } from 'react';

/**
 * The event feed, newest at the bottom, following the tail.
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
    <section>
      <h2>Events</h2>
      <ol data-testid="event-log">
        {events.map((event) => (
          <li key={event.id} data-event-type={event.eventType}>
            <time dateTime={event.createdAt}>{formatTime(event.createdAt)}</time>{' '}
            <span>{event.serviceName}</span>{' '}
            <span>{event.eventType}</span>{' '}
            <span>{event.message}</span>
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
  return Number.isNaN(parsed.getTime()) ? iso : parsed.toLocaleTimeString();
}
