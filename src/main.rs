use clap::{arg, value_parser, Command};
use std::str::FromStr;
use std::path::PathBuf;
use hex;

use std::collections::{HashMap, BTreeMap};
use std::convert::{From, TryFrom};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::{Identifier, Signature};
use frost_secp256k1_tr::keys::{
    KeyPackage, PublicKeyPackage, SecretShare,
    {dkg::round1, dkg::round2}
};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fs};
use ::bitcoin::key::{XOnlyPublicKey, PublicKey, UntweakedPublicKey, TapTweak};
use ::bitcoin::secp256k1::schnorr::{Signature as SchnorrSignature};
use ::bitcoin::secp256k1::Message;
use miniscript::bitcoin::hashes::hex::FromHex;
use miniscript::bitcoin::{Address, Network};
use miniscript::{DefiniteDescriptorKey, Descriptor};
use miniscript::bitcoin::psbt::PartiallySignedTransaction as Psbt;
use miniscript::psbt::{PsbtExt, PsbtInputExt};
use miniscript::bitcoin::sighash::SighashCache;
use miniscript::bitcoin::{
    self, psbt, secp256k1, OutPoint, Script, Transaction, TxIn, TxOut
};
use miniscript::bitcoin::consensus::encode::deserialize;

#[derive(Deserialize, Serialize, Debug)]
struct JSONDataWithShares {
    m: u16,
    n: u16,
    pubkey_package: PublicKeyPackage,
    shares: BTreeMap<Identifier, SecretShare>,
}

#[derive(Deserialize, Serialize, Debug)]
struct JSONData {
    m: u16,
    n: u16,
    pubkey_package: PublicKeyPackage,
    packages: BTreeMap<Identifier, KeyPackage>,
}

fn frost_gen_data_with_dealer(
    m: u16,
    n: u16,
) -> Option<JSONData> {
    let mut rng = thread_rng();
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        n, m, frost::keys::IdentifierList::Default, &mut rng
    ).unwrap();
    let mut packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for (idx, share) in shares.iter() {
        let package = KeyPackage::try_from(share.clone()).unwrap();
        packages.insert(*idx, package);
    }
    let json_data = JSONData {
        m,
        n,
        pubkey_package,
        packages,
    };
    Some(json_data)
}

fn frost_gen_data_dkg(
    m: u16,
    n: u16,
) -> Option<JSONData> {
    let mut rng = thread_rng();
    let ids = (1..=n)
        .map(|i| Identifier::try_from(i).expect("nonzero"))
        .collect::<Vec<_>>();
    // part1
    let mut r1_sec_packages: BTreeMap<Identifier, round1::SecretPackage> =
        BTreeMap::new();
    let mut r1_packages: BTreeMap<Identifier, round1::Package> =
        BTreeMap::new();
    for idx in ids.iter() {
        let (r1_sec_package, r1_package) = frost::keys::dkg::part1(
            *idx, n, m, &mut rng,
        ).unwrap();
        r1_sec_packages.insert(*idx, r1_sec_package);
        r1_packages.insert(*idx, r1_package);
    }
    // part2
    let mut r2_sec_packages: BTreeMap<Identifier, round2::SecretPackage> =
        BTreeMap::new();
    let mut r2_packages_map: BTreeMap<Identifier,
                                      BTreeMap<Identifier, round2::Package>> =
        BTreeMap::new();
    for idx in ids.iter() {
        let r1_sec_package = r1_sec_packages.get(idx).unwrap();
        let mut r1_others_packages = r1_packages.clone();
        r1_others_packages.remove(idx);
        let (r2_sec_package, r2_packages) =
            frost::keys::dkg::part2(
                r1_sec_package.clone(), &r1_others_packages
            ).unwrap();
        r2_sec_packages.insert(*idx, r2_sec_package);
        r2_packages_map.insert(*idx, r2_packages);
    }

    // part3
    let mut packages: BTreeMap<Identifier, KeyPackage> =
        BTreeMap::new();
    let mut pubkey_packages: BTreeMap<Identifier, PublicKeyPackage> =
        BTreeMap::new();
    for idx in ids.iter() {
        let mut r1_others_packages = r1_packages.clone();
        r1_others_packages.remove(idx);
        let r2_sec_package = r2_sec_packages.get(idx).unwrap();
        let mut r2_packages: BTreeMap<Identifier, round2::Package> =
            BTreeMap::new();
        for idx2 in ids.iter() {
            if idx2 != idx {
                let r2_others_packages = r2_packages_map.get(idx2).unwrap();
                r2_packages.insert(
                    *idx2, r2_others_packages.get(idx).unwrap().clone()
                );
            }
        }
        let (key_package, pubkey_package) = frost::keys::dkg::part3(
            r2_sec_package,
            &r1_others_packages,
            &r2_packages,
        ).unwrap();
        packages.insert(*idx, key_package);
        pubkey_packages.insert(*idx, pubkey_package);
    }

    let (_idx , pubkey_package) = pubkey_packages.iter().next_back().unwrap();
    let json_data = JSONData {
        m,
        n,
        pubkey_package: pubkey_package.clone(),
        packages,
    };
    Some(json_data)
}

fn read_json_with_shares(f_path: &PathBuf) -> JSONDataWithShares {
    let f_content = fs::read_to_string(&f_path).unwrap_or_else(|error| {
		panic!("Error reading file: \"{}\": {}", f_path.display(), error)
	});
    let json_data: JSONDataWithShares = serde_json::from_str(&f_content)
        .unwrap();
    json_data
}

fn read_json(f_path: &PathBuf) -> JSONData {
    let f_content = fs::read_to_string(&f_path).unwrap_or_else(|error| {
		panic!("Error reading file: \"{}\": {}", f_path.display(), error)
	});
    let json_data: JSONData = serde_json::from_str(&f_content).unwrap();
    json_data
}

fn get_vout(tx: &Transaction, spk: &Script) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == &txout.script_pubkey {
            return (OutPoint::new(tx.txid(), i as u32), txout);
        }
    }
    panic!("Only call get vout on functions which have the expected outpoint");
}

fn convert_shares_json(json_with_shares: &JSONDataWithShares) -> JSONData {
    let mut packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for (idx, share) in json_with_shares.shares.iter() {
        let package = KeyPackage::try_from(share.clone()).unwrap();
        packages.insert(*idx, package);
    }
    let json_data = JSONData {
        m: json_with_shares.m,
        n: json_with_shares.n,
        pubkey_package: json_with_shares.pubkey_package.clone(),
        packages,
    };
    json_data
}

fn get_group_address(json_data: &JSONData) -> Address {
    let verifying_key_b = json_data.pubkey_package.verifying_key();
    let pubk = PublicKey::from_slice(&verifying_key_b.serialize()[..]).unwrap();
    let xpubk = XOnlyPublicKey::from(pubk.inner);
    let xpubk_hex = hex::encode(&xpubk.serialize());
    let s = format!("tr({})", xpubk_hex);
    let d = Descriptor::<DefiniteDescriptorKey>::from_str(&s).unwrap();
    d.address(Network::Testnet).unwrap()
}

fn prepare_psbt(
    json_data: &JSONData,
    send_to: &String,
    amount: u64,
    prev_tx: &String,
) -> Psbt {
    let verifying_key_b = json_data.pubkey_package.verifying_key();
    let pubk = PublicKey::from_slice(&verifying_key_b.serialize()[..]).unwrap();
    let xpubk = XOnlyPublicKey::from(pubk.inner);
    let xpubk_hex = hex::encode(&xpubk.serialize());
    let s = format!("tr({})", xpubk_hex);
    let d = Descriptor::<DefiniteDescriptorKey>::from_str(&s).unwrap();
    let gaddr = d.address(Network::Testnet).unwrap();

    println!("Preparing transaction:");
    let spend_tx = Transaction {
        version: 2,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    let mut psbt = Psbt {
        unsigned_tx: spend_tx,
        version: 0,
        xpub: BTreeMap::new(),
        proprietary: BTreeMap::new(),
        unknown: BTreeMap::new(),
        inputs: vec![],
        outputs: vec![],
    };

    let depo_tx: Transaction = deserialize(
        &Vec::<u8>::from_hex(prev_tx).unwrap()
    ).unwrap();

    let receiver = Address::from_str(send_to).unwrap().assume_checked();
    let (outpoint, witness_utxo) = get_vout(&depo_tx, &d.script_pubkey());
    let mut txin = TxIn::default();
    txin.previous_output = outpoint;
    psbt.unsigned_tx.input.push(txin);

    let mut left_amount = witness_utxo.value;
    println!("Outpoint amount {} sats", left_amount);
    println!("add output to {}, amount {} sats", send_to, amount);
    psbt.unsigned_tx.output.push(TxOut {
        script_pubkey: receiver.script_pubkey(),
        value: amount,
    });
    left_amount -= amount;
    if left_amount > 330 * 2 + 300 { // dust * 2 + fee
        let change = left_amount - 300;
        left_amount -= change;
        println!("change to group address {}, amount {} sats", gaddr, change);
        psbt.unsigned_tx.output.push(TxOut {
            script_pubkey: gaddr.script_pubkey(),
            value: change,
        });
    }
    if left_amount > 0 {
        println!("Fee {} sats", left_amount);
    }

    let mut input = psbt::Input::default();
    input.update_with_descriptor_unchecked(&d).unwrap();

    input.witness_utxo = Some(witness_utxo.clone());
    psbt.inputs.push(input);
    psbt.outputs.push(psbt::Output::default());
    psbt
}

fn frost_sign(
    json_data: &JSONData,
    message: &[u8],
) -> Signature {
    let m = json_data.m;
    let mut rng = thread_rng();
    // Verifies the secret shares from the dealer and store them in a HashMap.
    // In practice, the KeyPackages must be sent to its respective participants
    // through a confidential and authenticated channel.
    let mut key_packages: HashMap<_, _> = HashMap::new();

    for (identifier, signing_share) in json_data.packages.clone() {
        let key_package = frost::keys::KeyPackage::try_from(signing_share);
        key_packages.insert(identifier, key_package);
    }

    let mut nonces_map = HashMap::new();
    let mut commitments_map = BTreeMap::new();
    // Round 1: generating nonces and signing commitments for each participant
    // In practice, each iteration of this loop will be executed by its
    // respective participant.
    for participant_index in 1..(m as u16 + 1) {
        let participant_identifier = participant_index.try_into().unwrap();
        let key_package = &key_packages[&participant_identifier].clone().unwrap();
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        let (nonces, commitments) = frost::round1::commit(
            key_package.signing_share(),
            &mut rng,
        );
        // In practice, the nonces must be kept by the participant to use in
        // the next round, while the commitment must be sent to the coordinator
        // (or to every other participant if there is no coordinator) using
        // an authenticated channel.
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = BTreeMap::new();
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    // Round 2: each participant generates their signature share
    // In practice, each iteration of this loop will be executed by its
    // respective participant.
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier].clone().unwrap();

        let nonces = &nonces_map[participant_identifier];

        // Each participant generates their signature share.
        let signature_share = frost::round2::sign(
            &signing_package, nonces, key_package
        ).unwrap();

        // In practice, the signature share must be sent to the Coordinator
        // using an authenticated channel.
        signature_shares.insert(*participant_identifier, signature_share);
    }

    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    // Aggregate (also verifies the signature shares)
    let group_signature = frost::aggregate(
        &signing_package, &signature_shares, &json_data.pubkey_package
    ).unwrap();
    //dbg!(&group_signature);

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    #[allow(unused)]
    let is_signature_valid = json_data.pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .is_ok();
    //dbg!(&is_signature_valid);
    group_signature
}

fn send_to_address(
    json_data: JSONData,
    send_to: &String,
    amount: u64,
    prev_tx: &String,
) {
    let verifying_key_b = json_data.pubkey_package.verifying_key();
    let mut psbt = prepare_psbt(&json_data, &send_to, amount, &prev_tx);

    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

    let msg = psbt
        .sighash_msg(0, &mut sighash_cache, None)
        .unwrap()
        .to_secp_msg();
    let msg_hex = format!("{:x}", msg);
    let message_b = hex::decode(msg_hex).unwrap();
    let message = message_b.as_ref();

    let group_signature = frost_sign(&json_data, &message);

    // add sig to psbt
    let hash_ty = bitcoin::sighash::TapSighashType::Default;
    let sighash_type =  bitcoin::psbt::PsbtSighashType::from(hash_ty);
    let sig_b = group_signature.serialize();
    let sig = SchnorrSignature::from_slice(&sig_b[1..]).unwrap();
    psbt.inputs[0].sighash_type = Option::Some(sighash_type);
    psbt.inputs[0].tap_key_sig = Option::Some(bitcoin::taproot::Signature {
        sig: sig,
        hash_ty: hash_ty,
    });

    let secp = secp256k1::Secp256k1::new();
    let pubk = PublicKey::from_slice(&verifying_key_b.serialize()[..]).unwrap();
    let utpk = UntweakedPublicKey::from(pubk.inner);
    #[allow(unused)]
    let (tpk, _) = utpk.tap_tweak(&secp, None);
    //dbg!(secp.verify_schnorr(&sig, &msg, &tpk.to_inner()));
    psbt.finalize_mut(&secp).unwrap();
    let tx = psbt.extract_tx();
    println!("\nDebug resulting Tx: \n{:#?}\n", &tx);
    let hex_tx = bitcoin::consensus::encode::serialize_hex(&tx);
    println!("Resulting Tx:\n{}", hex_tx);
}

fn test_tweaked_sign_verify(json_data: JSONData) {
    let mut message = [0; 32];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut message);
    let group_signature = frost_sign(&json_data, &message);
    let is_signature_valid = json_data.pubkey_package
        .verifying_key()
        .verify(&message, &group_signature)
        .is_ok();
    println!("is_signature_valid={}", is_signature_valid);
    let verifying_key_b = json_data.pubkey_package.verifying_key();
    let pubk = PublicKey::from_slice(&verifying_key_b.serialize()[..]).unwrap();
    let xpubk = XOnlyPublicKey::from(pubk.inner);
    let xpubk_hex = hex::encode(&xpubk.serialize());
    let s = format!("tr({})", xpubk_hex);
    let d = Descriptor::<DefiniteDescriptorKey>::from_str(&s).unwrap();
    use miniscript::Descriptor::{Tr};
    match d {
        Tr(v) => {
            let si = v.spend_info();
            println!("orig: {}", hex::encode(si.internal_key().serialize()));
            println!("spending: {}", hex::encode(si.output_key().serialize()));
            dbg!(si.output_key_parity());
            ()
        },
        _ => panic!("unknown"),
    }

    let secp = secp256k1::Secp256k1::new();
    let utpk = UntweakedPublicKey::from(pubk.inner);
    let (tpk, _) = utpk.tap_tweak(&secp, None);
    let sig_b = group_signature.serialize();
    let sig = SchnorrSignature::from_slice(&sig_b[1..]).unwrap();
    let msg = Message::from_slice(&message).unwrap();
    let secp_verify_res = match secp.verify_schnorr(&sig, &msg, &tpk.to_inner()) {
        Ok(_) => "Ok",
        Err(_) => "Invalid Signature",
    };
    println!("Check signature with secp256k1: {}", secp_verify_res);
}

fn cli() -> Command {
    Command::new("sign-tx-frost")
        .about("Tests on signing transactions with FROST/Taproot")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("generate")
                .about("Generate FROST parties data")
                .arg(
                    arg!(<m> "minimum number of signers")
                        .value_parser(value_parser!(u16).range(1..))
                )
                .arg(
                    arg!(<n> "maximum number of signers")
                        .value_parser(value_parser!(u16).range(2..))
                )
                .arg(
                    arg!(--dealer "use trusted dealer generation")
                )
                .arg(
                    arg!(--"test-tweaked" "Test sign with tweak on random data")
                )
                .arg_required_else_help(true)
        )
        .subcommand(
            Command::new("testsign")
                .about("Test sign/verify on early generated JSON data")
                .arg(
                    arg!(<PATH> "path of parties data JSON")
                        .default_value("testdata.json")
                        .required(false)
                        .value_parser(clap::value_parser!(PathBuf))
                )
        )
        .subcommand(
            Command::new("convert")
                .about("Convert JSON with SecretShare to KeyPackage format")
                .arg(
                    arg!(<PATH> "path of parties data JSON")
                        .default_value("testdata.json")
                        .required(false)
                        .value_parser(clap::value_parser!(PathBuf))
                )
        )
        .subcommand(
            Command::new("address")
                .about("Show taproot address for parties data public key")
                .arg(
                    arg!(<PATH> "path of parties data JSON")
                        .default_value("testdata.json")
                        .required(false)
                        .value_parser(clap::value_parser!(PathBuf))
                )
        )
        .subcommand(
            Command::new("sendtoaddress")
                .about("Create transaction to send amount to address")
                .arg(
                    arg!(<send_to> "address to send satoshis")
                        .value_parser(value_parser!(String))
                        .required(true)
                )
                .arg(
                    arg!(<amount> "amount of satoshis to send")
                        .value_parser(value_parser!(u64))
                        .required(true)
                )
                .arg(
                    arg!(<prev_tx> "hex of transaction used as input prevout")
                        .value_parser(value_parser!(String))
                        .required(true)
                )
                .arg(
                    arg!(<PATH> "path of parties data JSON")
                        .default_value("testdata.json")
                        .required(false)
                        .value_parser(clap::value_parser!(PathBuf))
                )
        )
}

pub fn type_of<T>(_: T) -> &'static str {
    std::any::type_name::<T>()
}

fn main() {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("generate", sub_matches)) => {
            let m = *sub_matches.get_one::<u16>("m").unwrap();
            let n = *sub_matches.get_one::<u16>("n").unwrap();
            let with_dealer = *sub_matches.get_one::<bool>("dealer")
                .unwrap();
            let test_tweak = *sub_matches.get_one::<bool>("test-tweaked")
                .unwrap();
            let json_data = if with_dealer {
                 frost_gen_data_with_dealer(m, n)
            } else {
                 frost_gen_data_dkg(m, n)
            };
            let json_str = serde_json::to_string_pretty(&json_data).unwrap();
            println!("{}\n", json_str);
            if test_tweak {
                test_tweaked_sign_verify(json_data.unwrap());
            }
        }
        Some(("testsign", sub_matches)) => {
            let f_path = sub_matches.get_one::<PathBuf>("PATH").unwrap();
            let json_data = read_json(f_path);
            test_tweaked_sign_verify(json_data);
        }
        Some(("convert", sub_matches)) => {
            let f_path = sub_matches.get_one::<PathBuf>("PATH").unwrap();
            let json_data = convert_shares_json(
                &read_json_with_shares(f_path)
            );
            let json_str = serde_json::to_string_pretty(&json_data).unwrap();
            println!("{}", json_str);
        }
        Some(("address", sub_matches)) => {
            let f_path = sub_matches.get_one::<PathBuf>("PATH").unwrap();
            let address = get_group_address(&read_json(f_path));
            println!("Address: {}", &address);
        }
        Some(("sendtoaddress", sub_matches)) => {
            let send_to = sub_matches.get_one::<String>("send_to").unwrap();
            let amount = *sub_matches.get_one::<u64>("amount").unwrap();
            let prev_tx = sub_matches.get_one::<String>("prev_tx")
                .unwrap();
            let f_path = sub_matches.get_one::<PathBuf>("PATH").unwrap();
            let json_data = read_json(&f_path);
            send_to_address(json_data, &send_to, amount, &prev_tx);
        }
        _ => {
            cli().print_help().unwrap();
        }
    }
}
