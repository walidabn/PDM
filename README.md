# PDM


# Structure : 
The code is divided in three main components for now : 
- pyServer : takes a list of floating point values, encodes them into integers (and split into bytes) before sending them to the bulletproof prover process. The first element of the list is the size of the list, to indicate until where the bulletproof prover process must read.
- bulletproof folder : contains the code for a client/prover in the ZKML scheme. It listens for data on port 3333 for a list of integer values. It then generates zero-knowledge range proofs via bulletproof, and then sends them to the bulletproofServer component on port 3334.
- bulletproofServer : receives data sent by bulletproof prover, and verifies the proof.

# How to run for now : 
- go into the bashLauncher folder, and on three separate terminals, run each bash script separately (sh Verifier.sh, sh Prover.sh , sh Data.sh)
- Each script just runs each process described in the structure section.