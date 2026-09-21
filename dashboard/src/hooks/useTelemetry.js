import { useState, useEffect, useRef, useCallback } from 'react';

const WS_URL = 'ws://localhost:8080/ws/telemetry';

/**
 * useTelemetry — Custom React hook for AetherGuard WebSocket telemetry.
 *
 * Connects to ws://localhost:8080/ws/telemetry, receives live security events,
 * maintains event history, stats counters, and connection state.
 *
 * @returns {Object} { events, stats, isConnected, clearEvents }
 */
export default function useTelemetry() {
  const [events, setEvents] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [stats, setStats] = useState({
    totalInspected: 0,
    quarantined: 0,
    authorized: 0,
    lastLatency: 0.08,
    circuitBreaker: 'NOMINAL',
  });

  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);

  const processEvent = useCallback((data) => {
    const isQuarantined =
      data.status === 'QUARANTINED' || data.status === 'CIRCUIT_BROKEN';

    setStats((prev) => ({
      ...prev,
      totalInspected: prev.totalInspected + 1,
      quarantined: isQuarantined ? prev.quarantined + 1 : prev.quarantined,
      authorized: !isQuarantined ? prev.authorized + 1 : prev.authorized,
      lastLatency: data.latency_ms || prev.lastLatency,
      circuitBreaker:
        data.status === 'CIRCUIT_BROKEN' ? 'TRIPPED' : prev.circuitBreaker,
    }));

    setEvents((prev) => [data, ...prev.slice(0, 99)]);

    return isQuarantined;
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
    setStats({
      totalInspected: 0,
      quarantined: 0,
      authorized: 0,
      lastLatency: 0.08,
      circuitBreaker: 'NOMINAL',
    });
  }, []);

  useEffect(() => {
    const connect = () => {
      try {
        const ws = new WebSocket(WS_URL);
        wsRef.current = ws;

        ws.onopen = () => {
          setIsConnected(true);
          console.log('[AetherGuard SOC] Telemetry WebSocket Connected.');
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);

            // Handle history batch on reconnection
            if (data.event_type === 'HISTORY_BATCH' && Array.isArray(data.data)) {
              setEvents((prev) => {
                const combined = [...data.data, ...prev];
                const seen = new Set();
                return combined
                  .filter((item) => {
                    const id = item.event_id || JSON.stringify(item);
                    if (seen.has(id)) return false;
                    seen.add(id);
                    return true;
                  })
                  .slice(0, 100);
              });
              return;
            }

            // Live event
            processEvent(data);
          } catch (err) {
            console.warn('Failed parsing WS message:', err);
          }
        };

        ws.onclose = () => {
          setIsConnected(false);
          reconnectTimerRef.current = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          setIsConnected(false);
        };
      } catch (e) {
        reconnectTimerRef.current = setTimeout(connect, 3000);
      }
    };

    connect();

    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
    };
  }, [processEvent]);

  return { events, stats, isConnected, clearEvents, processEvent };
}
