extern crate schnorrkel;
use merlin::Transcript;
use schnorrkel::{vrf::{VRFInOut, VRFPreOut, VRFProof}, Keypair, PublicKey};

const NUM_DRAWS : u8 = 8;
const NUM_CARDS : u16 = 52;

fn main() {
    println!("Welcome to poker using VRFs!");

    let vrf_seed = &[0u8; 32];

    let mut csprng = rand_core::OsRng;


    let keypair1 = Keypair::generate_with(&mut csprng);
    let draw1 = draws(&keypair1, vrf_seed);
    let (card1, signature1) = draw1[0];
    let public_key1 = keypair1.public;
    let reveal_card1 = recieve(&public_key1, &signature1, vrf_seed) ;
    println!("Revealed card for player1: {}", reveal_card1.unwrap()) ;
}


fn draw_transcript(seed: &[u8; 32], draw_num: u8) -> Option<Transcript> {
    if draw_num > NUM_DRAWS { return None; }
    let mut card_draw_transcript = Transcript::new(b"Card Draw Transcript");
    card_draw_transcript.append_message(b"seed",seed);
    card_draw_transcript.append_u64(b"draw", draw_num as u64);
    Some(card_draw_transcript)
}

fn find_card(vrf_output: &VRFInOut) -> Option<u16> {
    let card_bytes: [u8; 8] = vrf_output.make_bytes(b"card");
    Some( (u64::from_le_bytes(card_bytes) % (NUM_CARDS as u64)) as u16 )
}


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


fn draws(keypair: &Keypair, seed: &[u8; 32],) -> Vec<(u16, [u8; 97])>{
    (0..NUM_DRAWS).filter_map(|draw_num| try_draw(keypair, seed, draw_num)).collect()
}


fn recieve(public: &PublicKey, vrf_signature: &[u8; 97], seed: &[u8; 32]) -> Option<u16>{
    let transcript = draw_transcript(seed, vrf_signature[96]) ?;
    let vrf_pre_out = VRFPreOut::from_bytes(&vrf_signature[..32]).ok() ?;
    let proof = VRFProof::from_bytes(&vrf_signature[32..96]).ok() ?;
    let (vrf_in_out, _) = public.vrf_verify(transcript, &vrf_pre_out, &proof).ok() ?;
    find_card(&vrf_in_out)
}
