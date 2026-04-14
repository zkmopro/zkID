#!/bin/bash

usage() {
    echo "Usage: $0 {sha256rsa2048|sha256rsa4096|cert_chain_rs2048|cert_chain_rs4096|device_sig_rs2048|all}"
    echo "  sha256rsa2048:     Legacy monolithic circuit (MOICA-G2, RSA-2048)."
    echo "  sha256rsa4096:     Legacy monolithic circuit (MOICA-G3, RSA-4096 issuer / RSA-2048 user)."
    echo "  cert_chain_rs2048: Phase 2 split — Circuit A (cert chain + revocation) for MOICA-G2."
    echo "  cert_chain_rs4096: Phase 2 split — Circuit A for MOICA-G3 (4096-bit issuer, 2048-bit user)."
    echo "  device_sig_rs2048: Phase 2 split — Circuit B (device signature); always RSA-2048 (user keys are always 2048-bit)."
    echo "  all:               Compile all circuits (legacy + split)."
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
    cert_chain_rs2048)
        compile cert_chain_rs2048
    ;;
    cert_chain_rs4096)
        compile cert_chain_rs4096
    ;;
    device_sig_rs2048)
        compile device_sig_rs2048
    ;;
    all)
        compile sha256rsa2048
        compile sha256rsa4096
        compile cert_chain_rs2048
        compile cert_chain_rs4096
        compile device_sig_rs2048
    ;;
    *)
        echo "Error: Invalid option '$1'."
        usage
    ;;
esac
