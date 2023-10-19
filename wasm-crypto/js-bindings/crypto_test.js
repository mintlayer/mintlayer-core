// Use ES module import syntax to import functionality from the module
// that we have compiled.
//
// Note that the `default` import is an initialization function which
// will "boot" the module and make it ready to use. Currently browsers
// don't support natively imported WebAssembly as an ES module, but
// eventually the manual initialization won't be required!
import {
  make_private_key,
  public_key_from_private_key,
  sign_message,
  verify_signature,
  make_default_account_pubkey,
  make_receiving_address,
  pubkey_to_string,
  Network,
} from "../pkg/wasm_crypto.js";

export async function run_test() {
  // Try signature verification
  const priv_key = make_private_key();
  console.log(`priv key = ${priv_key}`);
  const pub_key = public_key_from_private_key(priv_key);
  console.log(`pub key = ${pub_key}`);
  const message = "Hello, world!";
  const signature = sign_message(priv_key, message);
  console.log(`signature = ${signature}`);
  const verified = verify_signature(pub_key, signature, message);
  console.log(`verified valid message with correct key = ${verified}`);
  if (!verified) {
    throw new Error("Signature verification failed!");
  }
  const verified_bad = verify_signature(pub_key, signature, "bro!");
  if (verified_bad) {
    throw new Error("Invalid message signature verification passed!");
  }

  // Attempt to use a bad private key to get a public key (test returned Result<> object, which will become a string error)
  const bad_priv_key = "bad";
  try {
    const bad_pub_key = public_key_from_private_key(bad_priv_key);
    throw new Error("Invalid private key worked somehow!");
  } catch (e) {
    if (!e.includes("Invalid private key encoding")) {
      throw new Error(
        "Invalid private key resulted in an unexpected error message!"
      );
    }
    console.log("Tested decoding bad private key successfully");
  }

  try {
    const invalid_mnemonic = "asd asd";
    make_default_account_pubkey(invalid_mnemonic, Network.Mainnet);
    throw new Error("Invalid mnemonic worked somehow!");
  } catch (e) {
    if (!e.includes("Invalid mnemonic string")) {
      throw e;
    }
    console.log("Tested invalid menemonic successfully");
  }

  try {
    make_receiving_address(bad_priv_key, 0);
    throw new Error("Invalid public key worked somehow!");
  } catch (e) {
    if (!e.includes("Invalid public key encoding")) {
      throw e;
    }
    console.log("Tested decoding bad account public key successfully");
  }

  const mnemonic = "walk exile faculty near leg neutral license matrix maple invite cupboard hat opinion excess coffee leopard latin regret document core limb crew dizzy movie";
  {
    const account_pubkey = make_default_account_pubkey(mnemonic, Network.Mainnet);
    console.log(`acc pubkey = ${account_pubkey}`);

    const receiving_pubkey = make_receiving_address(account_pubkey, 0);
    console.log(`receiving pubkey = ${receiving_pubkey}`);

    // test bad key index
    try {
      make_receiving_address(account_pubkey, 1<<31);
      throw new Error("Invalid key index worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid key index, MSB bit set")) {
        throw e;
      }
      console.log("Tested invalid key index with set MSB bit successfully");
    }

    const address = pubkey_to_string(receiving_pubkey, Network.Mainnet);
    console.log(`address = ${address}`);
    if (address != "mtc1qyqmdpxk2w42w37qsdj0e8g54ysvnlvpny3svzqx") {
      throw new Error("Incorrect address generated");
    }
  }


  {
    // Test generating an address for Testnet
    const account_pubkey = make_default_account_pubkey(mnemonic, Network.Testnet);
    console.log(`acc pubkey = ${account_pubkey}`);

    const receiving_pubkey = make_receiving_address(account_pubkey, 0);
    console.log(`receiving pubkey = ${receiving_pubkey}`);
    const address = pubkey_to_string(receiving_pubkey, Network.Testnet);
    console.log(`address = ${address}`);
    if (address != "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n") {
      throw new Error("Incorrect address generated");
    }
  }
}
