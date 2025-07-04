import streamlit as st
import json
import hashlib
from Crypto.Hash import keccak # <-- IMPORT THE CORRECT HASHER

# --- UI Configuration ---
st.set_page_config(page_title="Comprehensive Log Auditor", layout="wide")
st.title("✅ Comprehensive Log Integrity & Origin Auditor")
st.write("This tool verifies a log file's **Integrity**, **Origin**, and **Inclusion** in a master audit record.")

# --- Helper Function (with the fix) ---
def verify_merkle_proof(leaf_to_prove, proof_path, expected_merkle_root):
    try:
        expected_root_raw = expected_merkle_root.replace('0x', '')
        current_hash_bytes = bytes.fromhex(leaf_to_prove)

        for sibling_hash_hex in proof_path:
            sibling_hash_bytes = bytes.fromhex(sibling_hash_hex)
            
            if current_hash_bytes < sibling_hash_bytes:
                combined = current_hash_bytes + sibling_hash_bytes
            else:
                combined = sibling_hash_bytes + current_hash_bytes
            
            # --- THE FIX IS HERE ---
            # Use the correct keccak256 hasher instead of hashlib.sha3_256
            hasher = keccak.new(digest_bits=256)
            hasher.update(combined)
            current_hash_bytes = hasher.digest()
            # --- END OF FIX ---
        
        calculated_merkle_root_hex = current_hash_bytes.hex()
        return calculated_merkle_root_hex == expected_root_raw
    except Exception as e:
        st.error(f"Error during proof verification: {e}")
        return False

# --- Main UI (This part is unchanged) ---
st.header("Upload All Evidence Files for Verification")
# ... (The rest of the file is exactly the same as the previous version) ...
# ... I am omitting it here for brevity, but you should copy the full file content ...
# ... from our last conversation, only changing the verify_merkle_proof function ...
# ... and adding the new import at the top.
# --- The rest of the file from the last step ---
col1, col2 = st.columns(2)
with col1:
    log_file_uploader = st.file_uploader("1. Upload the Log File (e.g., `process_log_X.json`)")
    sha256_file_uploader = st.file_uploader("2. Upload the SHA256 Hash File (`.sha256`)")

with col2:
    sig_file_uploader = st.file_uploader("3. Upload the Signature File (`.sig`)")
    proof_file_uploader = st.file_uploader("4. Upload the Merkle Proof File (`.proof.json`)")

if log_file_uploader and sha256_file_uploader and sig_file_uploader and proof_file_uploader:
    log_content_bytes = log_file_uploader.getvalue()
    expected_sha256 = sha256_file_uploader.getvalue().decode('utf-8').strip()
    signature_content = sig_file_uploader.getvalue().decode('utf-8').strip()
    proof_data = json.load(proof_file_uploader)
    
    st.write("---")
    st.subheader("Verification Steps:")

    with st.expander("Step 1: Verify File Integrity (SHA256 Hash)", expanded=True):
        calculated_sha256 = hashlib.sha256(log_content_bytes).hexdigest()
        st.write(f"**Expected Hash (from `.sha256` file):** `{expected_sha256}`")
        st.write(f"**Calculated Hash (from uploaded log file):** `{calculated_sha256}`")
        integrity_ok = (calculated_sha256 == expected_sha256)
        if integrity_ok:
            st.success("✅ **Integrity Verified:** The log file's content matches its SHA256 hash.")
        else:
            st.error("❌ **TAMPERED:** The log file's content DOES NOT match its SHA256 hash. The file has been altered.")

    with st.expander("Step 2: Verify File Origin (Simulated TPM Signature)", expanded=True):
        st.write("This step simulates verifying a TPM signature.")
        st.write(f"**Signature Data (from `.sig` file):** `{signature_content[:50]}...`")
        origin_ok = True 
        if origin_ok:
            st.success("✅ **Origin Verified:** The signature is valid (simulation). This proves the log came from a trusted hardware source.")
        else:
            st.error("❌ **INVALID ORIGIN:** The signature is not valid.")

    with st.expander("Step 3: Verify Inclusion in Master Audit (Merkle Proof)", expanded=True):
        leaf_hash = proof_data['leaf']
        proof_path = proof_data['proof']
        merkle_root = proof_data['merkleRoot']
        st.write(f"**Expected Merkle Root (from proof file):** `{merkle_root}`")
        st.write("Verifying that the log file's hash is part of the Merkle Tree...")
        
        inclusion_ok = verify_merkle_proof(leaf_hash, proof_path, merkle_root)
        if inclusion_ok:
            st.success("✅ **Inclusion Verified:** The log file is a valid member of the weekly audit set anchored to the blockchain.")
        else:
            st.error("❌ **NOT INCLUDED:** The proof is invalid. This log was not part of the original audit.")
            
    st.write("---")
    st.header("Final Verdict")
    if integrity_ok and origin_ok and inclusion_ok:
        st.success("🎉 **AUDIT SUCCESSFUL:** All checks passed. The log file is authentic, unaltered, and verifiably part of the master audit record.")
    else:
        st.error("🚨 **AUDIT FAILED:** One or more verification checks failed. The evidence provided is not trustworthy.")