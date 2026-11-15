# Maintainer: KlamAV contributors
pkgname=klamav-git
pkgver=1.0.4.r0.g0000000
pkgrel=1
pkgdesc='KDE-friendly ClamAV antivirus frontend'
arch=('x86_64' 'aarch64')
url='https://github.com/asmerovski/KlamAV'
license=('GPL-3.0-or-later')
depends=('clamav' 'qt6-base' 'qt6-svg')
makedepends=('cmake' 'git' 'ninja')
provides=('klamav')
conflicts=('klamav')
source=('KlamAV::git+https://github.com/asmerovski/KlamAV.git#branch=main')
sha256sums=('SKIP')

pkgver() {
    cd "$srcdir/KlamAV"
    local version
    version="$(sed -n 's/^project(KlamAV VERSION \([^ ]*\).*/\1/p' CMakeLists.txt)"
    printf '%s.r%s.g%s' "$version" "$(git rev-list --count HEAD)" "$(git rev-parse --short=7 HEAD)"
}

build() {
    cmake -S "$srcdir/KlamAV" -B "$srcdir/build" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_TESTING=OFF
    cmake --build "$srcdir/build" --parallel
}

package() {
    DESTDIR="$pkgdir" cmake --install "$srcdir/build"
    install -Dm644 "$srcdir/KlamAV/LICENSE" \
        "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    install -Dm644 "$srcdir/KlamAV/README.md" \
        "$pkgdir/usr/share/doc/$pkgname/README.md"
}
