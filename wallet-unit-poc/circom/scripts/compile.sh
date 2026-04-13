#!/bin/bash

usage() {
    echo "Usage: $0 {sha256rsa2048|sha256rsa4096|all}"
    echo "  sha256rsa2048: Compile files for SHA256RSA2048."
    echo "  sha256rsa4096: Compile files for SHA256RSA4096."
    echo "  all: Compile all circuits."
    exit 1
}

if [ -z "$1" ]; then
    echo "Error: No option provided."
    usage
fi

function compile() {
    circuit_name=$1
    npx circomkit compile $circuit_name || { echo "Error: Failed to compile $circuit_name."; exit 1; }
    cd build/$circuit_name/ || { echo "Error: 'build/$circuit_name/' directory not found."; exit 1; }
    mv $circuit_name.r1cs ${circuit_name}_js/ || { echo "Error: Failed to move $circuit_name.r1cs."; exit 1; }
    cd ../.. || exit 1
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    cp -f build/$circuit_name/${circuit_name}_cpp/$circuit_name.cpp build/cpp/
    cp -f build/$circuit_name/${circuit_name}_cpp/$circuit_name.dat build/cpp/
    echo "$circuit_name circuit compiled successfully."
}


case "$1" in
    sha256rsa2048)
        compile sha256rsa2048
    ;;
    sha256rsa4096)
        compile sha256rsa4096
    ;;
    all)
        compile sha256rsa2048
        compile sha256rsa4096
    ;;
    *)
        echo "Error: Invalid option '$1'."
        usage
    ;;
esac
