#!/bin/bash
# SABLE Mobile Build Script
# Builds SABLE core library for Android and iOS platforms

set -e

echo "SABLE mobile packages are withdrawn (SBL-RT-004/008). See docs/security/REMEDIATION-2026-09-14.md." >&2
exit 1

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔧 SABLE Mobile Build Script${NC}"
echo "Building SABLE core library for mobile platforms..."

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Cargo is not installed. Please install Rust.${NC}"
    exit 1
fi

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# Create target directories
mkdir -p target/mobile/{android,ios}

# Build features
FEATURES="mobile,zk"

echo -e "${YELLOW}📱 Building for Android...${NC}"

# Android targets
ANDROID_TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi"
    "x86_64-linux-android"
)

for target in "${ANDROID_TARGETS[@]}"; do
    echo "  Building for $target..."
    
    # Check if target is installed
    if ! rustup target list --installed | grep -q "$target"; then
        echo "    Installing target $target..."
        rustup target add "$target"
    fi
    
    # Build the library
    cargo build --release --target "$target" --features "$FEATURES" -p sable-core
    
    # Copy to mobile target directory
    cp "target/$target/release/libsable_core.a" "target/mobile/android/libsable_core_$target.a"
    cp "target/$target/release/libsable_core.so" "target/mobile/android/libsable_core_$target.so" 2>/dev/null || true
done

echo -e "${YELLOW}🍎 Building for iOS...${NC}"

# iOS targets
IOS_TARGETS=(
    "aarch64-apple-ios"
    "x86_64-apple-ios"
    "aarch64-apple-ios-sim"
)

for target in "${IOS_TARGETS[@]}"; do
    echo "  Building for $target..."
    
    # Check if target is installed
    if ! rustup target list --installed | grep -q "$target"; then
        echo "    Installing target $target..."
        rustup target add "$target"
    fi
    
    # Build the library
    cargo build --release --target "$target" --features "$FEATURES" -p sable-core
    
    # Copy to mobile target directory
    cp "target/$target/release/libsable_core.a" "target/mobile/ios/libsable_core_$target.a"
done

echo -e "${YELLOW}🔗 Creating universal iOS library...${NC}"

# Create universal iOS library using lipo
if command -v lipo &> /dev/null; then
    lipo -create \
        "target/mobile/ios/libsable_core_aarch64-apple-ios.a" \
        "target/mobile/ios/libsable_core_x86_64-apple-ios.a" \
        "target/mobile/ios/libsable_core_aarch64-apple-ios-sim.a" \
        -output "target/mobile/ios/libsable_core_universal.a"
    echo "  Universal iOS library created: target/mobile/ios/libsable_core_universal.a"
else
    echo -e "${YELLOW}⚠️  lipo not found, skipping universal library creation${NC}"
fi

# Generate C headers for FFI
echo -e "${YELLOW}📄 Generating C headers...${NC}"

if command -v cbindgen &> /dev/null; then
    cbindgen --config cbindgen.toml --crate sable-core --output target/mobile/sable_mobile.h
    echo "  C header generated: target/mobile/sable_mobile.h"
    
    # Copy headers to platform directories
    cp target/mobile/sable_mobile.h platform/android/src/main/cpp/include/
    cp target/mobile/sable_mobile.h platform/ios/Sources/SableCCore/include/
else
    echo -e "${YELLOW}⚠️  cbindgen not found, skipping header generation${NC}"
fi

echo -e "${GREEN}✅ Mobile build completed successfully!${NC}"
echo ""
echo "📁 Build artifacts:"
echo "  Android: target/mobile/android/"
echo "  iOS: target/mobile/ios/"
echo "  Headers: target/mobile/sable_mobile.h"
echo ""
echo "🔧 Next steps:"
echo "  - Android: Use the .a/.so files in your CMake build"
echo "  - iOS: Link against libsable_core_universal.a in your Xcode project"
