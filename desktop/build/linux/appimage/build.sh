#!/usr/bin/env bash
# Builds the Bounty Runner AppImage with the engine sidecar inside.
#
# `wails3 generate appimage` takes only the app binary, so it runs first to
# produce the GTK/WebKit AppImage; that image is then extracted, the whole
# engine onedir is copied to usr/lib/bounty-run/engine (where runs.EngineBin
# finds it from usr/bin/bounty-runner), and the AppDir is repacked with the
# appimagetool bundled in the linuxdeploy that Wails downloaded, reusing the
# runtime of Wails' image. Nothing is linked or stripped inside the sidecar.
#
# Usage: build.sh <app binary> <icon.png> <desktop file> <engine dir> <work dir> <output dir>
set -euo pipefail

if [ "$#" -ne 6 ]; then
  echo "usage: $0 <app binary> <icon.png> <desktop file> <engine dir> <work dir> <output dir>" >&2
  exit 2
fi

abs() { (cd "$(dirname -- "$1")" && printf '%s/%s\n' "$(pwd)" "$(basename -- "$1")"); }
binary=$(abs "$1")
icon=$(abs "$2")
desktop=$(abs "$3")
engine=$(cd "$4" && pwd)
work=$5
outdir=$6
name=$(basename -- "$binary")

if [ ! -f "$engine/bounty-run" ] || [ ! -x "$engine/bounty-run" ]; then
  echo "error: $engine/bounty-run is not an executable file" >&2
  exit 1
fi
if [ ! -d "$engine/_internal" ]; then
  echo "error: $engine/_internal is missing (expected a PyInstaller onedir)" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) echo "error: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

mkdir -p "$work" "$outdir"
work=$(cd "$work" && pwd)
outdir=$(cd "$outdir" && pwd)
# work/build is kept between runs: Wails caches its linuxdeploy download there.
rm -rf "$work/stage" "$work/wails-out" "$work/squashfs-root" "$work/linuxdeploy"
mkdir -p "$work/stage" "$work/wails-out" "$work/build" "$work/linuxdeploy"

cp "$binary" "$work/stage/$name"
cp "$icon" "$work/stage/$name.png"

# 1. Wails' AppImage of the app alone (bundles GTK4/WebKitGTK via linuxdeploy).
wails3 generate appimage -binary "$work/stage/$name" -icon "$work/stage/$name.png" \
  -desktopfile "$desktop" -outputdir "$work/wails-out" -builddir "$work/build"

shopt -s nullglob
images=("$work"/wails-out/*.AppImage)
if [ "${#images[@]}" -ne 1 ]; then
  echo "error: expected one AppImage from wails3 generate appimage, found ${#images[@]}" >&2
  exit 1
fi
base=${images[0]}

# 2. Unpack it (the runtime's own extractor; no FUSE needed) and keep its runtime.
offset=$("$base" --appimage-offset)
head -c "$offset" "$base" >"$work/runtime"
(cd "$work" && "$base" --appimage-extract >/dev/null)
appdir="$work/squashfs-root"

# 3. Add the sidecar, byte for byte.
dest="$appdir/usr/lib/bounty-run/engine"
if [ -e "$dest" ]; then
  echo "error: $dest already exists in the Wails AppDir" >&2
  exit 1
fi
mkdir -p "$(dirname -- "$dest")"
cp -a "$engine" "$dest"
diff -r "$engine" "$dest" >/dev/null
# Wails' image carries 0700 directories, which appimagetool refuses (other
# users could not run the AppImage); open them up for reading only.
chmod -R a+rX "$appdir"

# 4. Repack with the appimagetool shipped inside Wails' linuxdeploy.
linuxdeploy="$work/build/linuxdeploy-$arch.AppImage"
(cd "$work/linuxdeploy" && "$linuxdeploy" --appimage-extract >/dev/null)
appimagetool="$work/linuxdeploy/squashfs-root/plugins/linuxdeploy-plugin-appimage/appimagetool-prefix/AppRun"
if [ ! -x "$appimagetool" ]; then
  echo "error: appimagetool not found in $linuxdeploy" >&2
  exit 1
fi
out="$outdir/$(basename -- "$base")"
rm -f "$out"
ARCH=$arch "$appimagetool" --no-appstream --runtime-file "$work/runtime" "$appdir" "$out"
chmod 0755 "$out"
echo "AppImage: $out"
