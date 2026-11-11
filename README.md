# KlamAV

KlamAV is a KDE-friendly ClamAV desktop frontend built with C++ and Qt 6 Widgets.
It provides an overview dashboard, quick/full/custom scans, quarantine, activity
history, and persistent scan and desktop preferences.

## Requirements

- CMake 3.21 or newer
- A C++17 compiler
- Qt 6.4 or newer (Widgets and Concurrent)
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

Build a package from the latest GitHub `main` branch with `makepkg -si`:

```sh
makepkg -si
```

The generated package installs the app-specific hicolor icon and KDE desktop
entry in the standard `/usr/share` locations.

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
- Startup login and system tray preferences are supported. Daily and weekly
  quick scans run while KlamAV is open. Real-time protection is a stored
  preference and is not activated by this build.
