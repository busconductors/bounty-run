// With api.js, the only frontend modules allowed to touch the Wails runtime.
import { Events, Window } from '@wailsio/runtime';

const report = (action) => (error) => console.error(`window ${action} failed`, error);

export const minimise = () => Window.Minimise().catch(report('minimise'));
export const toggleMaximise = () => Window.ToggleMaximise().catch(report('maximise'));
export const close = () => Window.Close().catch(report('close'));

// Subscribes to a backend event channel. callback receives the payload only.
// Returns the unsubscribe function.
export function onEvent(name, callback) {
  return Events.On(name, (event) => callback(event?.data ?? null));
}

// Drops every listener on the named channels.
export const off = (...names) => Events.Off(...names);
