# KlamAV

KlamAV is a KDE-friendly ClamAV desktop frontend built with C++ and Qt 6 Widgets.
It provides an overview dashboard, quick/full/custom scans, quarantine, activity
history, and persistent scan and desktop preferences.

## Requirements

- CMake 3.21 or newer
- A C++17 compiler
- Qt 6.4 or newer (Widgets, Concurrent, and Test)
- ClamAV (`clamdscan`, `freshclam`) and a running `clamd` daemon for scanning

## Build and run

```sh
cmake -S . -B build
cmake --build build
./build/klamav
```

Install the application and its desktop launcher with:

```sh
cmake --install build --prefix ~/.local
```

## Arch Linux package

The package version is read from the `project(... VERSION ...)` value in
`CMakeLists.txt`, so the PKGBUILD stays in sync with the app version. From the
project directory, build and install with:

```sh
makepkg -si
```

Install `base-devel`, `cmake`, `git`, `ninja`, `qt6-base`, `qt6-svg`, and
`clamav` first. The package builds from the latest GitHub `main` branch and
installs the app-specific hicolor icon and KDE desktop entry.

KlamAV also installs a Dolphin context-menu action. Select files or folders,
right-click, and choose **Scan with KlamAV**. The app opens to the scan page and
starts scanning the selected paths.

## Notes

- Scans enumerate files in the background and send bounded concurrent requests
  to `clamdscan`. The default is two workers; the CPU setting ranges from one
  worker to the number of available cores.
- The maximum file size, recursion, and symbolic-link preferences are applied
  by the frontend. Archive inspection depends on the ClamAV daemon configuration.
- Definition updates invoke `freshclam`; the configured daemon may require
  additional permissions or service configuration.
- Quarantined files are moved into the app's local data directory and restricted
  to the current user. Restores retain the original permissions and avoid
  overwriting an existing file.
- Startup login, system tray, and start-minimized preferences are supported.
  Starting minimized requires an available system tray and the tray icon
  preference to be enabled. Daily and weekly quick scans use a per-user
  systemd timer and can run while the window is closed. Scheduled scans require
  systemd user services and a running ClamAV daemon. Scanning is on demand;
  real-time protection is not active in this build.
- Settings can be saved from the page heading when values have changed. The
  sidebar shows the app version, and active jobs remain visible at the bottom
  of the window; the tray icon animates and lists running jobs in its tooltip.
- Build and run the core tests with `ctest --test-dir build --output-on-failure`.
