#!/bin/bash

# Requires 'afl-fuzz' package installed

PURPLE='\033[0;95m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

function log() {
    printf "${PURPLE}[+] $1${NC}\n"
}

if [ $# -ne 2 ]; then
    log "No input file argument supplied. Exiting."
    log "Usage: [ input.txt ] [ PK, KP, CP or MA ]\n"
    exit -1
fi

ARGC=$#
INPUT=$1
SCHEME=$2

if [[ ${SCHEME} -ne "PK" || ${SCHEME} -ne "KP" \
     || ${SCHEME} -ne "CP" || ${SCHEME} -ne "MA" ]]; then
    log "Usage: [ input.txt ] [ PK, KP, CP or MA ]\n"
    exit -1
fi

printf "Running tests for '${SCHEME}'\n"
echo "hello world!!!123456" > ${INPUT}

#set -x
AFL_FUZZER=$(which afl-fuzz)
AFL_C=$(which afl-clang)
AFL_CPP=$(which afl-clang++)

export CC="${AFL_C}" CXX="${AFL_CPP}"

log "Found '${AFL_C}' for C compiler..."
log "Found '${AFL_CPP}' for C++ compiler..."
log "Found '${AFL_FUZZER}' tool..."
#make clean
make


function run_fuzzer()
{
    name=$1
    ciphertext=$2
    target=$3
    set -x
    mkdir -p in_${name}
    mkdir -p out_${name}
    cp ${ciphertext} in_${name}/

    ${AFL_FUZZER} -i in_${name} -o out_${name} ${target}
    set +x
}

function assert()
{
    msg=$1; shift
    expected=$1; shift
    actual=$1; shift
    printf "${PURPLE}[+] $msg:${NC} "
    if [ "$expected" != "$actual" ]; then
        printf "${RED}FAILED with ERROR=$actual${NC}\n"
    else
        printf "${GREEN}PASSED${NC}\n"
    fi
}

function log_test() {
    printf "${PURPLE}- Testing $1${NC}\n"
}


function cleanup() {
    file=$1
    suffix=$2
    rm plainOK.${file} *.${suffix}
    rm -f *.key
}

function echo_line() {
    echo "********************************************"
}

#### TEST PK-ENC ####

if [ "${SCHEME}" = "PK" ]; then
    log_test "PK-ENC"
    ./oabe_keygen -s PK -i alice
    assert "Generate key for alice" 0 $?
    ./oabe_keygen -s PK -i bob
    assert "Generate key for bob" 0 $?
    ./oabe_keygen -s PK -i eve
    assert "Generate key for eve" 0 $?

    echo_line
    ./oabe_enc -s PK -e alice -r bob -i ${INPUT} -o ${INPUT}.pkenc
    assert "Encrypt ${INPUT} from alice to bob" 0 $?

    echo_line
    ./oabe_dec -s PK -e alice -r eve -i ${INPUT}.pkenc -o plainFail.${INPUT}
    assert "Decrypt as eve -- should fail" 32 $?

    echo_line
    ./oabe_dec -s PK -e alice -r bob -i ${INPUT}.pkenc -o plainOK.${INPUT}
    assert "Decrypt as bob -- should pass" 0 $?

    run_fuzzer pkenc ${INPUT}.pkenc "./oabe_dec -s PK -e alice -r bob -i @@ -o plainOK.${INPUT}"

    #cleanup ${INPUT} pkenc
    exit 0
fi

#### TEST PK-ENC ####

#### TEST CP-ABE ####

if [ "${SCHEME}" = "CP" ]; then
    echo_line
    echo ""
    echo_line
    log_test "CP-ABE"
    ./oabe_setup -s CP -p org1
    assert "Generate system parameters for CP" 0 $?

    ./oabe_keygen -s CP -p org1 -i "ONE|TWO|THREE" -o aliceCPABE
    assert "Generate key for alice" 0 $?

    ./oabe_keygen -s CP -p org1 -i "ONE|TWO|" -o bobCPABE
    assert "Generate key for bob" 0 $?


    echo_line
    ./oabe_enc -s CP -p org1 -e "((ONE and TWO) and THREE)" -i ${INPUT} -o ${INPUT}.cpabe
    assert "Encrypt under a simple policy" 0 $?

    echo_line
    ./oabe_dec -s CP -p org1 -k bobCPABE.key -i ${INPUT}.cpabe -o plainFail.${INPUT}
    assert "Decrypt using bob's key -- should fail" 22 $?

    echo_line
    ./oabe_dec -s CP -p org1 -k aliceCPABE.key -i ${INPUT}.cpabe -o plainOK.${INPUT}
    assert "Decrypt using alice's key -- should pass" 0 $?

    run_fuzzer cpabe ${INPUT}.cpabe "./oabe_dec -s CP -p org1 -k aliceCPABE.key -i @@ -o plainOK.${INPUT}"

    #cleanup ${INPUT} cpabe
    exit 0
fi
#### TEST CP-ABE ####

#### TEST KP-ABE ####

if [ "${SCHEME}" = "KP" ]; then
    echo_line
    echo ""
    echo_line
    log_test "KP-ABE"
    ./oabe_setup -s KP -p org2
    assert "Generate system parameters for KP" 0 $?

    ./oabe_keygen -s KP -p org2 -i "(ONE and (TWO or THREE))" -o aliceKPABE
    assert "Generate key for alice" 0 $?

    ./oabe_keygen -s KP -p org2 -i "(ONE and (TWO and FOUR))" -o bobKPABE
    assert "Generate key for bob" 0 $?

    echo_line
    ./oabe_enc -s KP -p org2 -e "ONE|TWO|THREE" -i ${INPUT} -o ${INPUT}.kpabe
    assert "Encrypt under three attributes" 0 $?

    echo_line
    ./oabe_dec -s KP -p org2 -k bobKPABE.key -i ${INPUT}.kpabe -o plainFail.${INPUT}
    assert "Decrypt using bob's key -- should fail" 22 $?

    echo_line
    ./oabe_dec -s KP -p org2 -k aliceKPABE.key -i ${INPUT}.kpabe -o plainOK.${INPUT}
    assert "Decrypt using alice's key -- should pass" 0 $?

    run_fuzzer kpabe ${INPUT}.kpabe "./oabe_dec -s KP -p org2 -k aliceKPABE.key -i @@ -o plainOK.${INPUT}"

    #cleanup ${INPUT} kpabe
    exit 0
fi
#### TEST KP-ABE ####

#set +x
