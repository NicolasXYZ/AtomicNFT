#!/bin/bash

# -e => Exits immediately on error
# -u => Error when using undefined vars
set -eu

USER_STATE="client/user-state.txt"
USER_SERVERKEYS="client/server-keys.txt"
AGG_STATE="aggregator/agg-state.txt"
AGG_ROOTSTATE="aggregator/agg-root-state.txt"
AGG_SERVERKEYS="aggregator/server-keys.txt"
AGG_FINALAGG="aggregator/final-agg.txt"
SERVER_STATE="server/server-state.txt"
SERVER_SHARES="server/shares.txt"
SERVER_SHARES_PARTIAL="server/partial_shares.txt"
SERVER_ROUNDOUTPUT="server/round_output.txt"

AGG_SERVICE_ADDR="localhost:8785"
SERVER_SERVICE_ADDR="localhost:8122"

# -q to reduce clutter
CMD_PREFIX="cargo run -q -- "

NUM_SERVERS=2
NUM_USERS=2
NUM_AGGREGATORS=1
NUM_USERS_PER_AGGREGATOR=2

NUM_TEST_ROUNDS=3

# We define four messages, separated by semicolons. The leading ; is because we index by 1
MSGS_STR=";testing;hello;world;yo"

# Checks that the given constants make sense
check() {
    if [[ $NUM_USERS -lt 1 ]]; then
        echo "Error: NUM_USERS must be at least 1"
        exit -1
    fi

    if [[ $NUM_AGGREGATORS -lt 1 ]]; then
        echo "Error: NUM_AGGREGATORS must be at least 1"
        exit -1
    fi

    if [[ $NUM_SERVERS -lt 1 ]]; then
        echo "Error: NUM_SERVERS must be at least 1"
        exit -1
    fi

    # If ceil(NUM_USERS / NUM_USERS_PER_AGGREGATOR) > NUM_AGGREGATORS, then this will fail
    if [[ \
        $(( ($NUM_USERS+$NUM_USERS_PER_AGGREGATOR-1) / $NUM_USERS_PER_AGGREGATOR)) \
        -gt $NUM_AGGREGATORS \
    ]]
    then
        echo "Error: NUM_USERS too high for the given NUM_AGGREGATORS"
        exit -1
    fi
}

# Removes all the intermediate files
clean() {
    # The below pattern removes all files of the form "client/user-stateX.txt" for any X
    rm -f ${USER_STATE%.txt}*.txt || true
    rm -f $USER_SERVERKEYS || true
    rm -f ${AGG_STATE%.txt}*.txt || true
    rm -f $AGG_ROOTSTATE || true
    rm -f $AGG_SERVERKEYS || true
    rm -f $AGG_FINALAGG || true
    rm -f ${SERVER_STATE%.txt}*.txt || true
    rm -f $SERVER_SHARES || true
    rm -f $SERVER_SHARES_PARTIAL || true
    rm -f ${SERVER_ROUNDOUTPUT%.txt}*.txt || true
    echo "Cleaned"
}

# Creates new servers and records their KEM pubkeys
setup_servers() {
    touch $USER_SERVERKEYS
    cd server

    # Accumulate the server registration data in this variable. The separator we use is ';'
    SERVER_REGS=""

    # Make a bunch of servers and save their pubkeys in client/ and aggregator/
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"

        # Make a new server and save the registration data
        SERVER_REG=$(
            $CMD_PREFIX new --server-state "../$STATE"
        )
        # Append
        if [[ i -eq 1 ]]; then
            SERVER_REGS="$SERVER_REG"
        else
            SERVER_REGS="$SERVER_REGS;$SERVER_REG"
        fi

        # Save the server pubkeys
        $CMD_PREFIX get-pubkeys --server-state "../$STATE" >> "../$USER_SERVERKEYS"
    done

    # Copy the pubkeys file to the aggregators
    cp "../$USER_SERVERKEYS" "../$AGG_SERVERKEYS"

    # Read the regs into a variable
    IFS=';' read -ra SERVER_REGS <<< "$SERVER_REGS"

    # Register the servers with each other
    i=1
    for SERVER_REG in "${SERVER_REGS[@]}"; do
        for j in $(seq 1 $NUM_SERVERS); do
            # Don't register any server with itself
            if [[ $i -eq $j ]]; then
                continue
            fi

            # Register server i with server j
            STATE="${SERVER_STATE%.txt}$j.txt"
            echo $SERVER_REG | $CMD_PREFIX register-server --server-state "../$STATE"
        done

        # Increment i
        i=$(($i + 1))
    done

    echo "Set up servers"
    cd ..
}

# Creates new aggregators wrt the server KEM pubkeys
setup_aggregators() {
    cd aggregator

    # Accumulate the aggregator registration data in this variable. The separator we use is ';'
    AGG_REGS=""

    # Make new base-level aggregators and capture the registration data
    for i in $(seq 1 $NUM_AGGREGATORS); do
        STATE="${AGG_STATE%.txt}$i.txt"
        AGG_REG=$(
            $CMD_PREFIX new --agg-state "../$STATE" --server-keys "../$AGG_SERVERKEYS"
        )

        # Append
        if [[ i -eq 1 ]]; then
            AGG_REGS="$AGG_REG"
        else
            AGG_REGS="$AGG_REGS;$AGG_REG"
        fi
    done

    # Make a new root aggregator and capture the registration data
    AGG_REG=$(
        $CMD_PREFIX new --agg-state "../$AGG_ROOTSTATE" --server-keys "../$AGG_SERVERKEYS"
    )
    AGG_REGS="$AGG_REGS;$AGG_REG"

    # Now do the registrations
    cd ../server

    # Read the regs into a variable
    IFS=';' read -ra AGG_REGS <<< "$AGG_REGS"

    # Register all the aggregators
    for AGG_REG in "${AGG_REGS[@]}"; do
        for i in $(seq 1 $NUM_SERVERS); do
            STATE="${SERVER_STATE%.txt}$i.txt"
            echo $AGG_REG | $CMD_PREFIX register-aggregator --server-state "../$STATE"
        done
    done

    echo "Set up aggregators"
    cd ..
}

# Creates new clients wrt the server KEM pubkeys
setup_clients() {
    cd client

    # Accumulate the client registration data in this variable. The separator we use is ';'
    USER_REGS=""

    # Make new clients and capture the registration data
    for i in $(seq 1 $NUM_USERS); do
        STATE="${USER_STATE%.txt}$i.txt"
        USER_REG=$(
            $CMD_PREFIX new --user-state "../$STATE" --server-keys "../$USER_SERVERKEYS"
        )

        # Append
        if [[ i -eq 1 ]]; then
            USER_REGS="$USER_REG"
        else
            USER_REGS="$USER_REGS;$USER_REG"
        fi
    done

    # Now do the registrations
    cd ../server

    # Read the regs into an array
    IFS=';' read -ra USER_REGS <<< "$USER_REGS"

    for USER_REG in "${USER_REGS[@]}"; do
        for i in $(seq 1 $NUM_SERVERS); do
            STATE="${SERVER_STATE%.txt}$i.txt"
            echo $USER_REG | $CMD_PREFIX register-user --server-state "../$STATE"
        done
    done

    echo "Set up clients"
    cd ..
}

# Starts round $ROUND with all the aggregators
start_round() {
    cd aggregator

    echo "Starting round $ROUND"

    # Start the base aggregators
    for i in $(seq 1 $NUM_AGGREGATORS); do
        STATE="${AGG_STATE%.txt}$i.txt"
        $CMD_PREFIX start-round --agg-state "../$STATE" --round $ROUND
    done
    # Start the root aggregator
    $CMD_PREFIX start-round --agg-state "../$AGG_ROOTSTATE" --round $ROUND

    cd ..
}

# Encrypts the messages and sends them to the aggregators
encrypt_msgs() {
    cd client

    # Read the messages into a variable
    IFS=';' read -ra MSGS <<< "$MSGS_STR"

    if [[ ${#MSGS[@]} -lt $NUM_USERS ]]; then
        echo "Error: we don't have enough sample messages for $NUM_USERS users"
        exit -1
    fi

    # Accumulate the ciphertexts. The separator we use is ';'
    CIPHERTEXTS=""

    # Encrypt all the messages in sequence
    for i in $(seq 1 $NUM_USERS); do
        STATE="${USER_STATE%.txt}$i.txt"
        MSG="${MSGS[$i]}"
        # Set the round output filename. If there was no previous round, it's /dev/null
        PREV_ROUND_OUTPUT=""
        if [[ $ROUND -eq 0 ]]; then
            PREV_ROUND_OUTPUT="/dev/null"
        else
            PREV_ROUND_OUTPUT="../${SERVER_ROUNDOUTPUT%.txt}$(($ROUND-1)).txt"
        fi

        # Encrypt
        CIPHERTEXT=$(
            echo -ne "$MSG" \
            | base64 \
            | $CMD_PREFIX encrypt-msg \
                  --user-state "../$STATE" \
                  --round $ROUND \
                  --prev-round-output $PREV_ROUND_OUTPUT
        )

        # Append
        if [[ i -eq 1 ]]; then
            CIPHERTEXTS="$CIPHERTEXT"
        else
            CIPHERTEXTS="$CIPHERTEXTS;$CIPHERTEXT"
        fi
    done

    # Read the ciphertexts into an array
    IFS=';' read -ra CIPHERTEXTS <<< "$CIPHERTEXTS"

    cd ..

    # Then send user messages to the base-level aggregators
    cd aggregator

    # Now send them to the base-level aggregators, parititoning the users
    i=0
    CURRENT_AGG=1
    for CIPHERTEXT in "${CIPHERTEXTS[@]}"; do
        # If we've already sent N ciphertext to this aggregator, switch to the next
        if [[ $i -eq $NUM_USERS_PER_AGGREGATOR ]]; then
            CURRENT_AGG=$(($CURRENT_AGG + 1))
            i=0
        fi
        STATE="${AGG_STATE%.txt}$CURRENT_AGG.txt"

        echo "$CIPHERTEXT" | $CMD_PREFIX input --agg-state "../$STATE"

        i=$(($i + 1))
    done

    echo "Encrypted messages"
    cd ..
}

# Propagates the base-level aggregates to the root aggregator
propagate_aggregates() {
    cd aggregator

    # Collect the second-to-top aggregates. Currently we only support two layers
    AGGS=""
    for i in $(seq 1 $NUM_AGGREGATORS); do
        STATE="${AGG_STATE%.txt}$i.txt"
        AGG=$($CMD_PREFIX finalize --agg-state "../$STATE")

        # Append
        if [[ i -eq 1 ]]; then
            AGGS="$AGG"
        else
            AGGS="$AGGS;$AGG"
        fi
    done

    # Read the aggregates into an array
    IFS=';' read -ra AGGS <<< "$AGGS"

    # Input all the aggregates into the root aggregator
    for AGG in "${AGGS[@]}"; do
        echo "$AGG" | $CMD_PREFIX input --agg-state "../$AGG_ROOTSTATE"
    done

    # Get the final aggregate
    $CMD_PREFIX finalize --agg-state "../$AGG_ROOTSTATE" > "../$AGG_FINALAGG"

    echo "Propagated aggregates"
    cd ..
}

# Decrypts the aggregated messages using the server's secrets
decrypt_msgs() {
    cd server

    # Create and clear the unblinded shares file
    touch "../$SERVER_SHARES"
    true > "../$SERVER_SHARES"

    # For each server, unblind the top-level aggregate and put them all in the server share file
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        $CMD_PREFIX unblind-aggregate --server-state "../$STATE" < "../$AGG_FINALAGG" \
            >> "../$SERVER_SHARES"
    done

    # Save all but the leader's share. This is for the service tests
    tail +2 "../$SERVER_SHARES" > "../$SERVER_SHARES_PARTIAL"

    # Now get the combined shares from the leader
    LEADER=1
    STATE="${SERVER_STATE%.txt}$LEADER.txt"
    ROUND_OUTPUT="${SERVER_ROUNDOUTPUT%.txt}$ROUND.txt"
    $CMD_PREFIX combine-shares --server-state "../$STATE" --shares "../$SERVER_SHARES" \
        > "../$ROUND_OUTPUT"

    # Have every server combine the shares as well. The output should be the same for all of them.
    # Don't save the output. Just visually inspect the logs.
    for i in $(seq 2 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        $CMD_PREFIX combine-shares --server-state "../$STATE" --shares "../$SERVER_SHARES" \
            > /dev/null
    done

    cd ..
}

clean
check

setup_servers
setup_aggregators
setup_clients

for ROUND in $(seq 0 $(($NUM_TEST_ROUNDS - 1))); do
    start_round
    encrypt_msgs
    propagate_aggregates
    decrypt_msgs
done
