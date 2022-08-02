#!/bin/bash

# -e => Exits immediately on error
# -u => Error when using undefined vars
set -eu

AGG_FINALAGG="aggregator/final-agg.txt"
SERVER_STATE="server/server-state.txt"
SERVER_SHARES="server/shares.txt"
SERVER_SHARES_PARTIAL="server/partial_shares.txt"

SERVER_LEADER_PORT="8522"

# -q to reduce clutter
CMD_PREFIX="cargo run -- "

# Assume wlog that the leading anytrust node is the first one
LEADER=1
NUM_FOLLOWERS=1

# Starts the anytrust leader
start_leader() {
    cd server

    STATE="${SERVER_STATE%.txt}$LEADER.txt"
    $CMD_PREFIX start-service \
        --server-state "../$STATE" \
        --bind "localhost:$SERVER_LEADER_PORT" &

    cd ..
}

# Starts the anytrust followers
start_followers() {
    cd server

    for i in $(seq 1 $NUM_FOLLOWERS); do
        FOLLOWER_PORT=$(($SERVER_LEADER_PORT + $i))
        STATE="${SERVER_STATE%.txt}$(($i+1)).txt"

        $CMD_PREFIX start-service \
            --server-state "../$STATE" \
            --bind "localhost:$FOLLOWER_PORT" \
            --leader-url "http://localhost:$SERVER_LEADER_PORT" &
    done

    cd ..
}

# Submits the toplevel aggregate to the leader and followers
submit_agg() {
    cd server

    for i in $(seq 0 $NUM_FOLLOWERS); do
        PORT=$(($SERVER_LEADER_PORT + $i))

        curl "http://localhost:$PORT/submit-agg" \
            -X POST \
            -H "Content-Type: text/plain" \
            --data-binary "@../$AGG_FINALAGG"
    done

    cd ..
}

# Submits the followers' shares to the leader
submit_shares() {
    cd server

    # Read the non-leaders' shares line by line
    while IFS="" read -r SHARE || [ -n "$SHARE" ]
    do
        # Send the share to the leader
        curl "http://localhost:$SERVER_LEADER_PORT/submit-share" \
            -X POST \
            -H "Content-Type: text/plain" \
            --data-binary "$SHARE"
    done < "../$SERVER_SHARES_PARTIAL"

    cd ..
}

# Returns the round result
get_round_result() {
    # Now get the round result
    curl -s "http://localhost:$SERVER_LEADER_PORT/round-result/$1"
}

kill_servers() {
    ps aux | grep sgxdcnet-server | grep -v grep | cut -d" " -f 7 | xargs kill
}

if [[ $1 == "start-leader" ]]; then
    start_leader
elif [[ $1 == "start-followers" ]]; then
    start_followers
elif [[ $1 == "submit-agg" ]]; then
    submit_agg
elif [[ $1 == "submit-shares" ]]; then
    submit_shares
elif [[ $1 == "round-result" ]]; then
    get_round_result $2
elif [[ $1 == "stop" ]]; then
    kill_servers
fi
