pkgname=klamav
pkgver="$(sed -n 's/^project(KlamAV VERSION \([0-9][0-9.]*\).*/\1/p' "$startdir/CMakeLists.txt")"
pkgrel=1
pkgdesc='Qt desktop frontend for ClamAV'
arch=('x86_64' 'aarch64')
license=('GPL-3.0-or-later')
depends=('qt6-base' 'clamav')
makedepends=('cmake' 'ninja')
source=()
sha256sums=()

prepare() {
    install -d "$srcdir/$pkgname"
    cp -a "$startdir/CMakeLists.txt" "$startdir/README.md" \
        "$startdir/LICENSE" "$startdir/src" "$startdir/data" \
        "$srcdir/$pkgname/"
}

build() {
    cmake -S "$srcdir/$pkgname" -B "$srcdir/$pkgname/build" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_TESTING=OFF
    cmake --build "$srcdir/$pkgname/build" --parallel
}

package() {
    DESTDIR="$pkgdir" cmake --install "$srcdir/$pkgname/build" --prefix /usr
    install -Dm644 "$srcdir/$pkgname/LICENSE" \
        "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
