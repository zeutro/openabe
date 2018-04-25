#!/bin/bash

PURPLE='\033[0;95m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

#set -x

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

function log() {
    printf "${PURPLE}[+] $1${NC}\n"
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

if [ $# -eq 0 ]; then
    log "No input file argument supplied. Exiting."
    exit -1
fi

INPUT=$1

#### TEST PK-ENC ####

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

cleanup ${INPUT} pkenc

#### TEST PK-ENC ####

#### TEST CP-ABE ####
echo_line
echo ""
echo_line
log_test "CP-ABE"
./oabe_setup -s CP -p org1
assert "Generate system parameters for CP" 0 $?

./oabe_keygen -s CP -p org1 -i "Female|Nurse|Floor=3|Respiratory_Specialist" -o aliceCPABE
assert "Generate key for alice" 0 $?

./oabe_keygen -s CP -p org1 -i "Male|Doctor|Floor=5|Cardiologist" -o charlieCPABE
assert "Generate key for bob" 0 $?


echo_line
./oabe_enc -s CP -p org1 -e "((Doctor or Nurse) and (Floor >= 3 and Floor < 5))" -i ${INPUT} -o ${INPUT}.cpabe
assert "Encrypt under a simple policy" 0 $?

echo_line
./oabe_dec -s CP -p org1 -k charlieCPABE.key -i ${INPUT}.cpabe -o plainFail.${INPUT}
assert "Decrypt using bob's key -- should fail" 32 $?

echo_line
./oabe_dec -s CP -p org1 -k aliceCPABE.key -i ${INPUT}.cpabe -o plainOK.${INPUT}
assert "Decrypt using alice's key -- should pass" 0 $?

cleanup ${INPUT} cpabe

#### TEST CP-ABE ####

#### TEST KP-ABE ####
echo_line
echo ""
echo_line
log_test "KP-ABE"
./oabe_setup -s KP -p org2
assert "Generate system parameters for KP" 0 $?

./oabe_keygen -s KP -p org2 -i "(From:Alice and (((Month:March and (Day >= 1 and Day <= 14)) or (Month:February and (Day > 22 and Day < 28))) and Year:2015))" -o analystKPABE
assert "Generate key for analyst" 0 $?

#./oabe_keygen -s KP -p org2 -i "(ONE and (TWO and FOUR))" -o bobKPABE
#a#ssert "Generate key for bob" 0 $?

echo_line
./oabe_enc -s KP -p org2 -e "From:Alice|To:Bob|Month:March|Day=7|Year:2015" -i ${INPUT} -o ${INPUT}1.kpabe
assert "Encrypt under three attributes" 0 $?

echo_line
./oabe_enc -s KP -p org2 -e "From:Alice|To:Charlie|Month:March|Day=15|Year:2015" -i ${INPUT} -o ${INPUT}2.kpabe
assert "Encrypt under three attributes" 0 $?

echo_line
./oabe_dec -s KP -p org2 -k analystKPABE.key -i ${INPUT}1.kpabe -o plainOK.${INPUT}
assert "Decrypt first CT using the analyst's key -- should pass" 0 $?

echo_line
./oabe_dec -s KP -p org2 -k analystKPABE.key -i ${INPUT}2.kpabe -o plainFail.${INPUT}
assert "Decrypt second CT using the analyst's key -- should fail" 32 $?

cleanup ${INPUT} kpabe

#### TEST KP-ABE ####

#set +x
