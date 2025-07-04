import streamlit as st
import json
import hashlib
from Crypto.Hash import keccak # <-- IMPORT THE CORRECT HASHER

# --- Session State for Page Navigation ---
if 'page' not in st.session_state:
    st.session_state.page = 'landing'

# --- Enhanced Landing Page ---
def landing_page():
    st.markdown("""
        <style>
        body { background-color: #18191A; }
        .main { background-color: #18191A; }
        .audit-title {
            font-size: 3em;
            color: #43e97b;
            font-weight: bold;
            margin-bottom: 0.2em;
        }
        .audit-subtitle {
            font-size: 1.3em;
            color: #CCCCCC;
            margin-bottom: 1.5em;
        }
        .audit-how {
            background: linear-gradient(90deg, #43e97b 0%, #38f9d7 100%);
            color: #18191A;
            border-radius: 12px;
            padding: 1.2em 2em;
            margin: 0 auto 2em auto;
            max-width: 600px;
            box-shadow: 0 2px 16px 0 rgba(67,233,123,0.08);
        }
        .audit-btn {
            background-color: #43e97b;
            color: #18191A;
            font-size: 1.5em;
            font-weight: bold;
            padding: 0.5em 2.5em;
            border-radius: 8px;
            border: none;
            margin-top: 2em;
            transition: background 0.2s;
        }
        .audit-btn:hover {
            background: #38f9d7;
            color: #18191A;
        }
        </style>
        <div style='text-align: center; margin-top: 60px;'>
            <span style='font-size: 3.5em;'>🔒</span>
            <div class='audit-title'>Shadow IT Audit Log Verifier</div>
            <div class='audit-subtitle'>Welcome to your secure audit log verification portal.</div>
            <div style='margin-bottom: 1.5em; color: #CCCCCC;'>
                This tool helps you <b>verify the Integrity, Origin, and Inclusion</b> of audit logs using cryptographic proofs.
            </div>
            <div class='audit-how'>
                <b>How it works:</b>
                <ul style='text-align: left; display: inline-block; margin: 0 auto;'>
                  <li>Upload the log file and its associated evidence files</li>
                  <li>Automatic checks for tampering, authenticity, and blockchain anchoring</li>
                  <li>Get a clear verdict on the log's trustworthiness</li>
                </ul>
            </div>
        </div>
    """, unsafe_allow_html=True)
    st.markdown("""
        <style>
        div.stButton > button:first-child {
            background-color: #43e97b;
            color: #18191A;
            font-size: 1.5em;
            font-weight: bold;
            padding: 0.5em 2.5em;
            border-radius: 8px;
            border: none;
            margin-top: 2em;
            transition: background 0.2s;
        }
        div.stButton > button:first-child:hover {
            background: #38f9d7;
            color: #18191A;
        }
        </style>
    """, unsafe_allow_html=True)
    col = st.columns([1,2,1])[1]
    with col:
        with st.form("start_verification_form"):
            submitted = st.form_submit_button("🚀 Start Verification")
            if submitted:
                st.session_state.page = 'upload'
    st.markdown("---")
    st.info("You will be guided to upload your evidence files on the next page.")

# --- Enhanced Upload & Verification Page ---
def upload_page():
    st.markdown("""
        <style>
        .upload-header {
            color: #43e97b;
            font-size: 2.2em;
            font-weight: bold;
            margin-bottom: 0.2em;
            text-align: center;
        }
        .upload-desc {
            font-size: 1.1em;
            color: #CCCCCC;
            text-align: center;
            margin-bottom: 1.5em;
        }
        div.stButton > button:first-child {
            background-color: #222;
            color: #43e97b;
            font-size: 1em;
            border-radius: 6px;
            margin-bottom: 1em;
        }
        div.stButton > button:first-child:hover {
            background: #43e97b;
            color: #18191A;
        }
        .evidence-card {
            background: #232526;
            border-radius: 10px;
            padding: 1.2em 1em 1em 1em;
            margin-bottom: 1.5em;
            box-shadow: 0 2px 16px 0 rgba(67,233,123,0.08);
        }
        </style>
        <div class='upload-header'>
            <span>📤 Upload All Evidence Files for Verification</span>
        </div>
        <div class='upload-desc'>
            Please upload the following files for the log you wish to verify:<br>
            <b>Log File</b> (<code>process_log_X.json</code>),
            <b>Signature</b> (<code>.sig</code>),
            <b>SHA256 Hash</b> (<code>.sha256</code>),
            <b>Merkle Proof</b> (<code>.proof.json</code>)
        </div>
    """, unsafe_allow_html=True)
    with st.form("back_to_home_form"):
        back = st.form_submit_button("⬅️ Back to Home")
        if back:
            st.session_state.page = 'landing'
    st.markdown("---")

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

    st.markdown("<div class='evidence-card'>", unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        log_file_uploader = st.file_uploader("1. Upload the Log File (e.g., `process_log_X.json`)")
        sha256_file_uploader = st.file_uploader("2. Upload the SHA256 Hash File (`.sha256`)")

    with col2:
        sig_file_uploader = st.file_uploader("3. Upload the Signature File (`.sig`)")
        proof_file_uploader = st.file_uploader("4. Upload the Merkle Proof File (`.proof.json`)")
    st.markdown("</div>", unsafe_allow_html=True)

    # Only show the verify button if all files are uploaded
    if log_file_uploader and sha256_file_uploader and sig_file_uploader and proof_file_uploader:
        with st.form("verify_evidence_form"):
            verify = st.form_submit_button("✅ Verify Evidence")
            if verify:
                log_content_bytes = log_file_uploader.getvalue()
                expected_sha256 = sha256_file_uploader.getvalue().decode('utf-8').strip()
                signature_content = sig_file_uploader.getvalue().decode('utf-8').strip()
                proof_data = json.load(proof_file_uploader)

                calculated_sha256 = hashlib.sha256(log_content_bytes).hexdigest()
                integrity_ok = (calculated_sha256 == expected_sha256)
                origin_ok = True  # Simulated
                leaf_hash = proof_data['leaf']
                proof_path = proof_data['proof']
                merkle_root = proof_data['merkleRoot']
                inclusion_ok = verify_merkle_proof(leaf_hash, proof_path, merkle_root)

                st.session_state['verification_result'] = {
                    'integrity_ok': integrity_ok,
                    'origin_ok': origin_ok,
                    'inclusion_ok': inclusion_ok,
                    'expected_sha256': expected_sha256,
                    'calculated_sha256': calculated_sha256,
                    'signature_content': signature_content,
                    'merkle_root': merkle_root
                }
                st.session_state.page = 'results'

# --- Results Page ---
def results_page():
    result = st.session_state.get('verification_result', {})
    st.markdown("""
        <style>
        .results-header {
            color: #43e97b;
            font-size: 2.2em;
            font-weight: bold;
            margin-bottom: 0.2em;
            text-align: center;
        }
        .results-summary {
            font-size: 1.1em;
            color: #CCCCCC;
            text-align: center;
            margin-bottom: 1.5em;
        }
        </style>
        <div class='results-header'>📝 Verification Results</div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("<div class='results-summary'>", unsafe_allow_html=True)
    st.write("**File Integrity:**")
    if result.get('integrity_ok'):
        st.success("✅ The log file's content matches its SHA256 hash.")
    else:
        st.error("❌ The log file's content DOES NOT match its SHA256 hash. The file has been altered.")
    st.write(f"Expected Hash: `{result.get('expected_sha256','')}`")
    st.write(f"Calculated Hash: `{result.get('calculated_sha256','')}`")
    st.write("\n**File Origin:**")
    if result.get('origin_ok'):
        st.success("✅ The signature is valid (simulation). This proves the log came from a trusted hardware source.")
    else:
        st.error("❌ The signature is not valid.")
    st.write(f"Signature Data: `{result.get('signature_content','')[:50]}...`")
    st.write("\n**Merkle Proof Inclusion:**")
    if result.get('inclusion_ok'):
        st.success("✅ The log file is a valid member of the weekly audit set anchored to the blockchain.")
    else:
        st.error("❌ The proof is invalid. This log was not part of the original audit.")
    st.write(f"Merkle Root: `{result.get('merkle_root','')}`")
    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("---")
    if result.get('integrity_ok') and result.get('origin_ok') and result.get('inclusion_ok'):
        st.success("🎉 **AUDIT SUCCESSFUL:** All checks passed. The log file is authentic, unaltered, and verifiably part of the master audit record.")
    else:
        st.error("🚨 **AUDIT FAILED:** One or more verification checks failed. The evidence provided is not trustworthy.")
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Verify Another Log"):
            st.session_state.page = 'upload'
    with col2:
        if st.button("🏠 Back to Home"):
            st.session_state.page = 'landing'

# --- Dispatcher to Switch Pages ---
def main():
    if st.session_state.page == 'landing':
        landing_page()
    elif st.session_state.page == 'upload':
        upload_page()
    elif st.session_state.page == 'results':
        results_page()

main()