
extern crate rand;
extern crate curve25519_dalek;
use curve25519_dalek::ristretto::CompressedRistretto;


extern crate merlin;
use merlin::Transcript;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};

// SERVER code that VERIFIES a proof received from client
// This server listens on port 3334



fn handle_client_single(mut stream: TcpStream) {
    let mut data = [0 as u8; 1000]; // using 1000 byte buffer
    let mut counter = 0;
    let nb_bits = 8;
    while match stream.read(&mut data) {
        Ok(size) => {
            if counter == 0 {
            println!("Printing received data");
            println!("{:?}",data);
            //data[0] = 8; if you try to modify stuff in the commitment you get an error which is good
            let c = &data[0..32];
            let p = &data[32..32+480];
            let commit = CompressedRistretto::from_slice(&c);
            let proof = RangeProof::from_bytes(&p).unwrap();
            println!("Printing received commit");
            println!("{:?}",commit);
            println!("Printing received proof");
            println!("{:?}",proof);
            
            let pc_gens = PedersenGens::default();


            let bp_gens = BulletproofGens::new(64, 1);
            let mut verifier_transcript = Transcript::new(b"doctest example");
            if proof.verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &commit, nb_bits).is_ok(){
                println!("Proof verified with success!");
            } else {
                println!("Proof verification failed!");
            }


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
    let mut data = [0 as u8; 1000]; // using 1000 byte buffer
    let mut counter = 0;
    let nb_bits = 32;
    let nb_values = 4;
    let log_nb_values : usize = (nb_values as f64).log2().floor() as usize;

    while match stream.read(&mut data) {
        Ok(size) => {
            if counter == 0 {
            //println!("Printing received data");
            //println!("{:?}",data);
            //data[0] = 8; if you try to modify stuff in the commitment you get an error which is good
            let offset = nb_values*32;
            let c = &data[0..offset];
            let p = &data[offset..offset+608+64*log_nb_values];
            let mut commit : Vec<CompressedRistretto> = Vec::new();
            for i in 0..nb_values{
                commit.push(CompressedRistretto::from_slice(&c[i*32..(i+1)*32]));
            }
            /*
            println!("Constructed commitment");
            println!("Printing received commit");
            println!("{:?}",commit);*/

            let proof = RangeProof::from_bytes(&p).unwrap();
            /*
            println!("Printing received commit");
            println!("{:?}",commit);
            println!("Printing received proof");
            println!("{:?}",proof);*/
            
            let pc_gens = PedersenGens::default();



            let bp_gens = BulletproofGens::new(64, nb_values);
            let mut verifier_transcript = Transcript::new(b"doctest example");
            if proof.verify_multiple(&bp_gens, &pc_gens, &mut verifier_transcript, &commit, nb_bits).is_ok(){
                println!("Proof verified with success!");
            } else {
                println!("Proof verification failed!");
            }


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




    let listener = TcpListener::bind("0.0.0.0:3334").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3334");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    // connection succeeded
                    //handle_client_single(stream)
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