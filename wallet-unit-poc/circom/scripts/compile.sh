#!/bin/bash

usage() {
  echo "Usage: $0 {jwt_rs256|all}"
  echo "  jwt_rs256: Compile files for JWT-RS256."
  echo "  all: Compile all circuits."
  exit 1
}

if [ -z "$1" ]; then
  echo "Error: No option provided."
  usage
fi

case "$1" in
  jwt_rs256)
    npx circomkit compile jwt_rs256 || { echo "Error: Failed to compile JWT-RS256."; exit 1; }
    cd build/jwt_rs256/ || { echo "Error: 'build/jwt_rs256/' directory not found."; exit 1; }
    mv jwt_rs256.r1cs jwt_rs256_js/ || { echo "Error: Failed to move jwt_rs256.r1cs."; exit 1; }
    cd ../.. || exit 1
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    [ ! -f build/cpp/jwt_rs256.cpp ] && cp build/jwt_rs256/jwt_rs256_cpp/jwt_rs256.cpp build/cpp/ || true
    [ ! -f build/cpp/jwt_rs256.dat ] && cp build/jwt_rs256/jwt_rs256_cpp/jwt_rs256.dat build/cpp/ || true
    echo "JWT-RS256 file processing complete."
    ;;
  all)
    echo "Compiling all circuits..."
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    npx circomkit compile jwt_rs256 || { echo "Error: Failed to compile JWT-RS256."; exit 1; }
    cd build/jwt_rs256/ && mv jwt_rs256.r1cs jwt_rs256_js/ && cd ../.. || { echo "Error: Failed to process JWT-RS256."; exit 1; }
    [ ! -f build/cpp/jwt_rs256.cpp ] && cp build/jwt_rs256/jwt_rs256_cpp/jwt_rs256.cpp build/cpp/ || true
    [ ! -f build/cpp/jwt_rs256.dat ] && cp build/jwt_rs256/jwt_rs256_cpp/jwt_rs256.dat build/cpp/ || true
    echo "All circuits compiled successfully."
    ;;
  *)
    echo "Error: Invalid option '$1'."
    usage
    ;;
esac
