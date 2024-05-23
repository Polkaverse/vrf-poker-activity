extern crate schnorrkel;
use merlin::Transcript;
use schnorrkel::{vrf::{VRFInOut, VRFPreOut, VRFProof}, Keypair, PublicKey};

const NUM_DRAWS : u8 = 8;
const NUM_CARDS : u16 = 52;

fn main() {
    println!("Welcome to poker using VRFs!");

    let vrf_seed = &[0u8; 32];

    // OsRng is an implementation of a cryptographically secure pseudorandom number generator.
    let mut secure_rng = rand_core::OsRng;

    // Generating keypairs for all players
    let keypair1 = Keypair::generate_with(&mut secure_rng);
    let keypair2 = Keypair::generate_with(&mut secure_rng) ;
    let keypair3 = Keypair::generate_with(&mut secure_rng);
    let keypair4 = Keypair::generate_with(&mut secure_rng);

    // Draw cards for all players.
    let draw1 = draws(&keypair1, vrf_seed);
    let draw2 = draws(&keypair2, vrf_seed);
    let draw3 = draws(&keypair3, vrf_seed);
    let draw4 = draws(&keypair4, vrf_seed);

    // Assuming we are only interested in the first draw.
    let (card1, signature1) = draw1[0] ;
    let (card2, signature2) = draw2[0] ;
    let (card3, signature3) = draw3[0] ;
    let (card4, signature4) = draw4[0] ;

    // Creating a vector which consist each players draw cards.
    let mut players = Vec::new() ;
    players.push((1, card1)) ;
    players.push((2, card2)) ;
    players.push((3, card3)) ;
    players.push((4, card4)) ;

    let highest_drawn_card = winner(players) ;

    match highest_drawn_card {
        Some((1, _)) => println!("Player 1 wins!") ,
        Some((2, _)) => println!("Player 2 wins!") ,
        Some((3, _)) => println!("Player 3 wins!") ,
        Some((4, _)) => println!("Player 4 wins!") ,
        _ => println!("No winner"),
    }

    // Optionally, revealing cards using receive function.
    let public_key1 = keypair1.public ;
    let public_key2 = keypair2.public ;
    let public_key3 = keypair3.public ;
    let public_key4 = keypair4.public ;

    let reveal_card1 = recieve(&public_key1, &signature1, vrf_seed) ;
    let reveal_card2 = recieve(&public_key2, &signature2, vrf_seed) ;
    let reveal_card3 = recieve(&public_key3, &signature3, vrf_seed) ;
    let reveal_card4 = recieve(&public_key4, &signature4, vrf_seed) ;

    println!("Revealed card for player1: {}", reveal_card1.unwrap()) ;
    println!("Revealed card for player2: {}", reveal_card2.unwrap()) ;
    println!("Revealed card for player3: {}", reveal_card3.unwrap()) ;
    println!("Revealed card for player4: {}", reveal_card4.unwrap()) ;
}

/// Creates a transcript for a card draw operation.
///
/// This function generates a new transcript for a card draw operation using the provided seed and draw number.
/// If the draw number exceeds the maximum allowed number of draws, the function returns None.
///
/// # Arguments
///
/// * seed - A 32-byte slice representing the seed used for the card draw.
/// * draw_num - The number of the draw operation.
///
/// # Returns
///
/// An Option<Transcript> containing the generated transcript if the draw number is valid, or None otherwise.
fn draw_transcript(seed: &[u8; 32], draw_num: u8) -> Option<Transcript> {
    if draw_num > NUM_DRAWS { return None; }
    let mut card_draw_transcript = Transcript::new(b"Card Draw Transcript");
    card_draw_transcript.append_message(b"seed",seed);
    card_draw_transcript.append_u64(b"draw", draw_num as u64);
    Some(card_draw_transcript)
}

/// Finds the card number based on VRF input/output.
///
/// This function calculates the card number based on the VRF input/output provided.
/// The VRF input/output is converted into bytes using the specified label "card", and
/// the card number is determined by performing a modulo operation on the resulting bytes.
///
/// # Arguments
///
/// * vrf_output - A reference to the VRF input/output (VRFInOut) from which the card number is derived.
fn find_card(vrf_output: &VRFInOut) -> Option<u16> {
    let card_bytes: [u8; 8] = vrf_output.make_bytes(b"card");
    Some( (u64::from_le_bytes(card_bytes) % (NUM_CARDS as u64)) as u16 )
}

/// Tries to draw a card and generate a VRF signature.
///
/// This function attempts to draw a card by generating a VRF signature using the provided keypair,
/// seed, and draw number. It constructs a transcript, signs it using the VRF keypair, and then
/// generates a VRF signature containing the card information along with the proof and draw number.
///
/// # Arguments
///
/// * keypair - A reference to the keypair (Keypair) used to sign the transcript.
/// * seed - A 32-byte slice representing the seed used for the card draw.
/// * draw_num - The number of the draw operation.
///
/// # Returns
///
/// An Option containing a tuple (u16, [u8; 97]) representing the card number and VRF signature
/// if the draw is successful, or None if any step of the process fails.
fn try_draw(keypair: &Keypair, seed: &[u8; 32], draw_num: u8) -> Option<(u16, [u8; 97])> {
    let transcript = draw_transcript(seed, draw_num) ?;
    let (vrf_in_out, proof, _) = keypair.vrf_sign(transcript);
    let card = find_card(&vrf_in_out)?;
    let mut vrf_signature = [0u8; 97];
    vrf_signature[..32].copy_from_slice(& vrf_in_out.to_preout().to_bytes()[..]);
    vrf_signature[32..96].copy_from_slice(& proof.to_bytes()[..]);
    vrf_signature[96] = draw_num;
    Some((card, vrf_signature))
}

/// Draws multiple cards and generates VRF signatures.
///
/// This function draws multiple cards and generates VRF signatures for each draw operation
/// using the provided keypair and seed. It iterates over the specified number of draws,
/// attempting to draw a card and generate a VRF signature for each draw. Draws that fail
/// to produce a valid signature are filtered out, and the successful draws are collected
/// into a vector of tuples containing the card number and VRF signature.
///
/// # Arguments
///
/// * keypair - A reference to the keypair (Keypair) used to sign the transcripts.
/// * seed - A 32-byte slice representing the seed used for the card draws.
///
/// # Returns
///
/// A vector of tuples (u16, [u8; 97]) representing the card numbers and VRF signatures
/// for the successful draw operations.
fn draws(keypair: &Keypair, seed: &[u8; 32],) -> Vec<(u16, [u8; 97])>{
    (0..NUM_DRAWS).filter_map(|draw_num| try_draw(keypair, seed, draw_num)).collect()
}

/// Verifies a card play using the provided public key, VRF signature, and seed.
///
/// This function reconstructs the transcript using the seed and the draw number
/// extracted from the VRF signature, verifies the VRF proof, and then determines
/// the card associated with the verified VRF input/output. It returns the card
/// number if the verification is successful.
///
/// # Arguments
///
/// * public - A reference to the PublicKey used to verify the VRF proof.
/// * vrf_signature - A slice of 97 bytes containing the VRF preoutput (32 bytes),
///   the VRF proof (64 bytes), and the draw number (1 byte).
/// * seed - A 32-byte slice representing the seed used to generate the transcript.
///
/// # Returns
///
/// An Option<u16> containing the card number if the verification is successful,
/// or None if any step of the verification process fails.
/// This function is to ensure the integrity and uniqueness of the data of draws.
///
/// Compute the actual card draw from VRF inputs and outputs,
/// divide by the total card outcomes, and map to the drawn card index.

/// This function will pick a card from the drawn cards.
///
/// This function Draws all our cards for the given seed.
fn recieve(public: &PublicKey, vrf_signature: &[u8; 97], seed: &[u8; 32]) -> Option<u16>{
    let transcript = draw_transcript(seed, vrf_signature[96]) ?;
    let vrf_pre_out = VRFPreOut::from_bytes(&vrf_signature[..32]).ok() ?;
    let proof = VRFProof::from_bytes(&vrf_signature[32..96]).ok() ?;
    let (vrf_in_out, _) = public.vrf_verify(transcript, &vrf_pre_out, &proof).ok() ?;
    find_card(&vrf_in_out)
}

/// Determines the winner among the players based on the highest card number.
///
/// This function takes a vector of player-card tuples and determines the winner based on
/// the highest card number. If the vector is empty, indicating no players, it returns None.
/// Otherwise, it returns a tuple containing the player ID and the card number of the winner.
///
/// # Arguments
///
/// * players - A vector of tuples (u8, u16) representing the player ID and their respective card numbers.
///
/// # Returns
///
/// An Option containing a tuple (u8, u16) representing the player ID and the card number of the winner,
/// or None if there are no players.
fn winner(players: Vec<(u8, u16)>) -> Option<(u8, u16)> {
    if players.is_empty(){
        None
    }
    else {
        Some(*players.iter().max_by_key(|&(_, card)| card).unwrap())
    }
}
