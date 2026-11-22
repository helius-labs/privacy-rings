# Source from the repository root after building the CLI.

start_localnet_scope() {
    local prefix=$1
    shift
    localnet_ports=("$@")
    ZOLANA_PROCESS_SCOPE_DIR="$(mktemp -d "$(pwd -P)/target/$prefix.XXXXXX")"
    export ZOLANA_PROCESS_SCOPE_DIR
    export ZOLANA_CONFIG_DIR="$ZOLANA_PROCESS_SCOPE_DIR/config"
    trap stop_localnet_scope EXIT
    mkdir "$ZOLANA_CONFIG_DIR"
}

stop_localnet_scope() {
    local status=$?
    if ! target/debug/zolana dev start --stop "${localnet_ports[@]}"; then
        status=1
    fi
    if (( status == 0 )); then
        rm -rf -- "$ZOLANA_PROCESS_SCOPE_DIR"
    else
        printf 'Localnet files are in %s\n' "$ZOLANA_PROCESS_SCOPE_DIR" >&2
    fi
    exit "$status"
}
