// The only frontend module allowed to touch the Wails runtime.
import { Window } from '@wailsio/runtime';

const report = (action) => (error) => console.error(`window ${action} failed`, error);

export const minimise = () => Window.Minimise().catch(report('minimise'));
export const toggleMaximise = () => Window.ToggleMaximise().catch(report('maximise'));
export const close = () => Window.Close().catch(report('close'));
