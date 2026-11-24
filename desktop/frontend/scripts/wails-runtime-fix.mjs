// Build-time fix for @wailsio/runtime (3.1.0, still present in 3.2.0 nightlies):
// drag.js only attaches its mouse listeners when isMobile() is false, and
// isMobile() falls back to a user-agent regex even when the backend has
// already reported a desktop OS. WebKitGTK on ARM64 Linux reports
// "(Linux; like Android 4.4) ... Mobile Safari", the regex matches "android",
// and the frameless window can never be dragged or edge-resized.
//
// The patch makes a known environment.OS authoritative and keeps the UA
// heuristic only for when the environment is not set yet. If upstream changes
// the code, the build fails rather than silently shipping an undraggable window.

const DRAG_MODULE = /[\\/]@wailsio[\\/]runtime[\\/]dist[\\/]drag\.js$/;

const ORIGINAL = `    if (os === "ios" || os === "android")
        return true;`;

const PATCHED = `    if (os)
        return os === "ios" || os === "android";`;

export function patchDragModule(source) {
  const normalised = source.replace(/\r\n/g, '\n');
  if (!normalised.includes(ORIGINAL)) {
    throw new Error(
      'wails-runtime-fix: @wailsio/runtime drag.js isMobile() no longer matches; ' +
        'check whether upstream fixed the desktop-OS check and drop or update this plugin',
    );
  }
  return normalised.replace(ORIGINAL, PATCHED);
}

export function wailsRuntimeFix() {
  return {
    name: 'wails-runtime-fix',
    enforce: 'pre',
    transform(code, id) {
      if (!DRAG_MODULE.test(id.split('?')[0])) return null;
      return { code: patchDragModule(code), map: null };
    },
  };
}
