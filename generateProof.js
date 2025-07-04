const { MerkleTree } = require('merkletreejs');
const keccak256 = require('keccak256');
const fs = require('fs');
const path = require('path');

// --- Main Script ---
function generateProof() {
  // 1. Get the target filename from the command line arguments
  const targetLogFileName = process.argv[2];
  if (!targetLogFileName) {
    console.error("\n❌ Error: You must specify which log file to generate a proof for.");
    console.error("   Usage: node generateProof.js <log_file_name>");
    console.error("   Example: node generateProof.js process_log_2.json\n");
    process.exit(1);
  }
  console.log(`--- Generating Merkle Proof for: ${targetLogFileName} ---`);

  // 2. Load the main audit data file
  const auditDataPath = path.join('./audit_output', 'audit_data.json');
  if (!fs.existsSync(auditDataPath)) {
    console.error("❌ Error: audit_data.json not found. Please run runAudit.js first.");
    return;
  }
  const auditData = JSON.parse(fs.readFileSync(auditDataPath, 'utf8'));
  const { cids, merkleRoot } = auditData;
  console.log(`Loaded Merkle Root: ${merkleRoot}`);

  // 3. Re-create the Merkle Tree from all the CIDs
  const leaves = cids.map(cid => keccak256(cid));
  const tree = new MerkleTree(leaves, keccak256, { sortPairs: true });

  // 4. Find the index of the log file we want to prove
  const fileIndexMatch = targetLogFileName.match(/_(\d+)\.json$/);
  if (!fileIndexMatch) {
    console.error("❌ Error: Log file name must be in the format 'process_log_X.json'");
    process.exit(1);
  }
  const logFileIndex = parseInt(fileIndexMatch[1], 10);
  if (logFileIndex >= cids.length) {
    console.error(`❌ Error: Index ${logFileIndex} is out of bounds. Only ${cids.length} logs were processed.`);
    process.exit(1);
  }

  // 5. Generate the proof for that specific log file's CID
  const logToProveCID = cids[logFileIndex];
  const leafToProve = keccak256(logToProveCID);
  const proof = tree.getProof(leafToProve);
  console.log("Generated Proof (a list of sibling hashes):", proof.map(p => p.data.toString('hex')));

  // 6. Verify the proof locally (good practice)
  const isVerified = tree.verify(proof, leafToProve, tree.getRoot());
  if (!isVerified) {
    console.error("❌ Local verification failed! Something is wrong.");
    return;
  }
  console.log("✅ Local verification successful.");

  // 7. Save the proof to a file with a matching name
  const proofData = {
    logFile: targetLogFileName,
    cid: logToProveCID,
    leaf: leafToProve.toString('hex'),
    proof: proof.map(p => p.data.toString('hex')),
    merkleRoot: merkleRoot,
  };

  // Create a better output filename, e.g., 'process_log_2.json.proof'
  const proofFileName = `${targetLogFileName}.proof.json`;
  const proofFilePath = path.join('./audit_output', 'proofs', proofFileName);
  fs.writeFileSync(proofFilePath, JSON.stringify(proofData, null, 2));
  console.log(`\n✅ Merkle Proof saved to: ${proofFilePath}`);
  console.log(`\n-> For the auditor, provide the log file from the 'logs' folder and this new proof file from the 'proofs' folder.`);
}

generateProof();