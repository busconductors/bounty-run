// Rail order and labels from the UI spec. Icons are 16px square-geometry paths.
export const VIEWS = Object.freeze([
  { id: 'launch', label: 'Launch', icon: 'M4 2.5 13 8 4 13.5Z' },
  { id: 'monitor', label: 'Monitor', icon: 'M1.5 8.5h3l2-5 3 9 2-4h3' },
  { id: 'runs', label: 'Runs', icon: 'M2 4h12M2 8h12M2 12h12' },
  { id: 'findings', label: 'Findings', icon: 'M3 3h10v10H3ZM8 1v4M8 11v4M1 8h4M11 8h4' },
  { id: 'doctor', label: 'Doctor', icon: 'M6 2h4v4h4v4h-4v4H6v-4H2V6h4Z' },
  { id: 'settings', label: 'Settings', icon: 'M2 4h6M11 4h3M8.5 2v4M2 12h3M8 12h6M5.5 10v4' },
]);

export const DEFAULT_VIEW = VIEWS[0].id;
