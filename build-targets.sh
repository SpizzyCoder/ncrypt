#!/bin/bash

TARGETS=(
  "i686-pc-windows-gnu"
  "i686-unknown-linux-gnu"
  "x86_64-pc-windows-gnu"
  "x86_64-unknown-linux-gnu"
)

mkdir -p target_binaries
rm -rf target_binaries/*

for TARGET in "${TARGETS[@]}"; do
  echo "Building for ${TARGET}..."
  cargo build --quiet --release --target ${TARGET}
  if [[ "${TARGET}" == *"windows"* ]]; then
    mv target/${TARGET}/release/ncrypt.exe target_binaries/ncrypt_${TARGET}.exe
  else
    mv target/${TARGET}/release/ncrypt target_binaries/ncrypt_${TARGET}
  fi
done
