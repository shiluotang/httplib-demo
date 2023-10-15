#!/usr/bin/env bash

function mksdir() {
    for d in "${@}"; do
        if [[ ! -d "${d}" ]]; then
            mkdir -p "${d}"
        fi
    done
}

function main() {
    mksdir bin build-aux m4
    if [[ ! -f ./configure ]]; then
        if ! autoreconf -vfi; then
            rm configure
            return 1
        fi
    fi
    if [[ ! -f bin/Makefile ]]; then
        if pushd bin >& /dev/null; then
            if ! ../configure "${@}"; then
                rm Makefile
                popd >& /dev/null
                return 1
            fi
            popd >& /dev/null
        fi
    fi
    if [[ -f bin/Makefile ]]; then
        local BEAR=
        if command -v bear >& /dev/null; then
            BEAR="bear --append -- "
        fi
        ${BEAR} make -C bin all
        ${BEAR} make -C bin check
    fi
}

main "${@}"
