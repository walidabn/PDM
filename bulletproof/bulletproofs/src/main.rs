
extern crate rand;
use rand::thread_rng;
extern crate curve25519_dalek;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
extern crate merlin;
use merlin::Transcript;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};


use std::io::{Read, Write};
use std::str::from_utf8;

use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};

use std::convert::TryInto;

// This is the CLIENT/PROVER code in the crypto layer of the ZKML project, also a SERVER for the pythonClient.
// The server part listens on port 3333 and sends to another server listening on port 3334

fn fromVecToBytes<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

// convert with left byte as lsb
fn as_u32_be(array: &[u8],start:usize) -> u32 {
    ((array[start] as u32) << 0) +
    ((array[start+1] as u32) << 8) +
    ((array[start+2] as u32) << 16) +
    ((array[start+3] as u32) <<  24)
}


// Takes a secret value we want to prove lies in the range [0, 2^32)
fn generate_commit_and_proof(secret_value : u64) -> (RangeProof, CompressedRistretto)  {

    // Generators for Pedersen commitments.  These can be selected
// independently of the Bulletproofs generators.
let pc_gens = PedersenGens::default();

// Generators for Bulletproofs, valid for proofs up to bitsize 64
// and aggregation size up to 1.
let bp_gens = BulletproofGens::new(64, 1);


// The API takes a blinding factor for the commitment.
let blinding = Scalar::random(&mut thread_rng());

// The proof can be chained to an existing transcript.
// Here we create a transcript with a doctest domain separator.
let mut prover_transcript = Transcript::new(b"doctest example");
let n_bits = 8;
// Create a 32-bit rangeproof.
let (proof, committed_value) = RangeProof::prove_single(
    &bp_gens,
    &pc_gens,
    &mut prover_transcript,
    secret_value,
    &blinding,
    n_bits,
).expect("A real program could handle errors");

return (proof,committed_value);
}

fn send_proof_single(to : String, sv : u32){

    // to = "localhost:3334"
match TcpStream::connect(to) {
    Ok(mut stream) => {
        println!("Successfully connected to server in port 3334");

        let secret_value = sv as u64;
        let (proof,committed_value) = generate_commit_and_proof(secret_value);
        let commit_msg = committed_value.to_bytes();
        let proof_msg = proof.to_bytes();
        let c = CompressedRistretto::from_slice(&commit_msg);
        let p = RangeProof::from_bytes(&proof_msg).unwrap();
        //println!("Printing commit : {:?}",c);
        //println!("Printing proof : {:?}",p);
        
        
        let msg : Vec<u8> = commit_msg.iter().cloned().chain(proof_msg.iter().cloned()).collect();
        //let msg = fromVecToBytes(m);
        stream.write(&msg).unwrap();
        println!("Sent msg value, awaiting reply...");


        let mut data= Vec::with_capacity(msg.len());

       // [0 as u8; msg.len()]; // using 32 byte buffer

        match stream.read_to_end(&mut data) {
            Ok(_) => {

                if &data == &msg {
                    println!("{:?}",msg);
                    println!("Reply is ok!");
                
                } else {
                    let text = from_utf8(&data).unwrap();
                    println!("Unexpected reply: {}", text);
                }
            },
            Err(e) => {
                println!("Failed to receive data: {}", e);
            }
        }
    },
    Err(e) => {
        println!("Failed to connect: {}", e);
    }
}
println!("Terminated.");


}

fn generate_commit_and_proof_multiple(vector_size : usize, secret_vector : Vec<u64>) -> (RangeProof, Vec<CompressedRistretto>) {
// Generators for Pedersen commitments.  These can be selected
// independently of the Bulletproofs generators.
let pc_gens = PedersenGens::default();

// Generators for Bulletproofs, valid for proofs up to bitsize 64
// and aggregation size up to vector_length.
let bp_gens = BulletproofGens::new(64, vector_size);

// The API takes blinding factors for the commitments.
let blindings: Vec<_> = (0..vector_size).map(|_| Scalar::random(&mut thread_rng())).collect();


// The proof can be chained to an existing transcript.
// Here we create a transcript with a doctest domain separator.
let mut prover_transcript = Transcript::new(b"doctest example");

let n_bits = 32;

// Create an aggregated 32-bit rangeproof and corresponding commitments.
let (proof, commitments) = RangeProof::prove_multiple(
    &bp_gens,
    &pc_gens,
    &mut prover_transcript,
    &secret_vector,
    &blindings,
    n_bits,
).expect("A real program could handle errors");


let mut verifier_transcript = Transcript::new(b"doctest example");
assert!(
    proof
        .verify_multiple(&bp_gens, &pc_gens, &mut verifier_transcript, &commitments, n_bits)
        .is_ok()
);

return (proof,commitments);



}


fn send_proof_multiple(to : String, sv :  Vec<u32>){

        // to = "localhost:3334"
match TcpStream::connect(to) {
    Ok(mut stream) => {
        println!("Successfully connected to server in port 3334");
        let secret_vector : Vec<_> = sv.iter().map(|&e| e as u64).collect(); // map 32 bit to 64
        let (proof,committed_values) = generate_commit_and_proof_multiple(secret_vector.len(),secret_vector); // RangeProof + Vec<CompressedRistretto>
        //println!("Printing commited_values");
        //((println!("{:?}",committed_values);
        //println!("Printing proof");
        //println!("{:?}",proof);
        let commit_msg : Vec<_> = committed_values.iter().flat_map(|e| e.to_bytes()).collect(); // size 32 bytes * #commitments
        let proof_msg = proof.to_bytes(); // size 608 + log2(#commitments)*64
        
        
        let msg : Vec<u8> = commit_msg.iter().cloned().chain(proof_msg.iter().cloned()).collect(); // concatenate commitments||proof
        stream.write(&msg).unwrap();
        println!("Sent msg value, awaiting reply...");


        let mut data= Vec::with_capacity(msg.len());

        // [0 as u8; msg.len()]; // using 32 byte buffer

        match stream.read_to_end(&mut data) {
            Ok(_) => {

                if &data == &msg {
                    //println!("{:?}",msg);
                    println!("Reply is ok!");
                
                } else {
                    let text = from_utf8(&data).unwrap();
                    println!("Unexpected reply: {}", text);
                }
            },
            Err(e) => {
                println!("Failed to receive data: {}", e);
            }
        }
    },
    Err(e) => {
        println!("Failed to connect: {}", e);
    }
}
println!("Terminated.");




}


fn handle_client_single(mut stream: TcpStream) {
    let mut data = [0 as u8; 1000]; // using 50 byte buffer
    let mut counter = 0;
    while match stream.read(&mut data) {
        Ok(size) => {
            if counter == 0 {
            //println!("Printing received data");
            //println!("{:?}",data);
            let py_u32= as_u32_be(&data,0);
            println!("Printing Python u32 length value : {:}",py_u32);
            let to = "localhost:3334";
            send_proof_single(to.try_into().unwrap(), py_u32);
            }
            stream.write(&data[0..size]).unwrap();
            counter = counter + 1;
            true
        },
        Err(_) => {
            println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
}

fn handle_client_multiple(mut stream: TcpStream) {
    let mut data = [0 as u8; 10000]; 
    let mut counter = 0;
    while match stream.read(&mut data) {
        Ok(size) => {
            if counter == 0 {
            //println!("Printing received data");
            //println!("{:?}",data);
            let length_vector= as_u32_be(&data,0);
            let size_vector = length_vector as usize;
            println!("Printing Python u32 length value : {:}",length_vector);
            let mut secret_vector : Vec<u32> = vec![0; size_vector];
            for i in 0..size_vector {
                secret_vector[i] = as_u32_be(&data,4*(i+1));
            } 
            let to = "localhost:3334";
            send_proof_multiple(to.try_into().unwrap(), secret_vector);
            }
            stream.write(&data[0..size]).unwrap();
            counter = counter + 1;
            true
        },
        Err(_) => {
            println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
}




fn main() {

    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3333");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    // connection succeeded
                    handle_client_multiple(stream)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
                /* connection failed */
            }
        }
    }
    // close the socket server
    drop(listener);
   
    

}