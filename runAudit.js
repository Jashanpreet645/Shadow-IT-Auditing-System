const { MerkleTree } = require('merkletreejs');
const keccak256 = require('keccak256');
const crypto = require('crypto');
const fs = require('fs');
const { execSync } = require('child_process');
const path = require('path');

// --- CONFIGURATION ---
const IPFS_API_URL = "http://127.0.0.1:5001";
const COMPANY_ID = "MyAwesomeCorp";
const WEEK_ID = `2024-W${Math.floor(new Date().getDate() / 7) + 1}`;
const LOG_FILES_TO_GENERATE = 5;

// --- DIRECTORY CONFIGURATION ---
const OUTPUT_DIR = './audit_output';
const LOGS_DIR = path.join(OUTPUT_DIR, 'logs');
const PROOFS_DIR = path.join(OUTPUT_DIR, 'proofs');

// --- HELPER FUNCTIONS ---

function generateProcessLog(fileName) {
  console.log(`[Member 1] Generating process log: ${fileName}`);
  const filePath = path.join(LOGS_DIR, fileName);
  try {
    const command = 'powershell "Get-Process | Select-Object ProcessName, Id, StartTime | ConvertTo-Json"';
    const logContent = execSync(command, { encoding: 'utf8' });
    fs.writeFileSync(filePath, logContent);
    console.log(`   -> Saved to ${filePath}`);
  } catch (error) {
    fs.writeFileSync(filePath, JSON.stringify([{ "ProcessName": "node", "Id": 1234 }]));
    console.log(`   -> Created a fallback log at ${filePath}.`);
  }
}

function signAndHashLog(fileName) {
  console.log(`[Member 2] Signing and hashing log: ${fileName}`);
  const logPath = path.join(LOGS_DIR, fileName);
  const logContent = fs.readFileSync(logPath);
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const signer = crypto.createSign('sha256');
  signer.update(logContent).end();
  const signature = signer.sign(privateKey, 'hex');
  const sigPath = path.join(PROOFS_DIR, `${fileName}.sig`);
  fs.writeFileSync(sigPath, signature);
  console.log(`   -> Signature saved to ${sigPath}`);
  const hash = crypto.createHash('sha256').update(logContent).digest('hex');
  const hashPath = path.join(PROOFS_DIR, `${fileName}.sha256`);
  fs.writeFileSync(hashPath, hash);
  console.log(`   -> SHA256 hash saved to ${hashPath}`);
}

async function uploadToIPFS(fileName) {
  console.log(`[Member 3] Uploading to IPFS: ${fileName}`);
  
  // THE FIX IS HERE: We use dynamic import() inside the async function
  const { create } = await import('ipfs-http-client');

  const filePath = path.join(LOGS_DIR, fileName);
  const ipfs = create({ url: IPFS_API_URL });
  const fileContent = fs.readFileSync(filePath);
  const { cid } = await ipfs.add(fileContent);
  console.log(`   -> IPFS CID: ${cid.toString()}`);
  return cid.toString();
}

// --- MAIN EXECUTION ---
async function main() {
  console.log(`--- Starting Provable Audit for ${COMPANY_ID}, ${WEEK_ID} ---`);

  fs.mkdirSync(LOGS_DIR, { recursive: true });
  fs.mkdirSync(PROOFS_DIR, { recursive: true });
  console.log(`Organizing output in: ${OUTPUT_DIR}`);

  const logFileNames = [];
  for (let i = 0; i < LOG_FILES_TO_GENERATE; i++) {
    const fileName = `process_log_${i}.json`;
    generateProcessLog(fileName);
    logFileNames.push(fileName);
  }
  
  const cids = [];
  for (const fileName of logFileNames) {
    signAndHashLog(fileName);
    const cid = await uploadToIPFS(fileName);
    cids.push(cid);
  }
  
  console.log("\n[Member 4] Building Merkle Tree from all CIDs...");
  const leaves = cids.map(x => keccak256(x));
  const tree = new MerkleTree(leaves, keccak256, { sortPairs: true });
  const merkleRoot = tree.getRoot().toString('hex');
  console.log("   -> Merkle Root:", `0x${merkleRoot}`);
  
  const auditData = { companyId: COMPANY_ID, weekId: WEEK_ID, cids, merkleRoot: `0x${merkleRoot}` };
  const summaryPath = path.join(OUTPUT_DIR, 'audit_data.json');
  fs.writeFileSync(summaryPath, JSON.stringify(auditData, null, 2));
  console.log(`✅ Audit data and Merkle Root saved to ${summaryPath}`);
  console.log("\n--- Next step: Deploy the contract, then run `submitRoot.js` ---");
}

main().catch(error => { console.error("An error occurred:", error); process.exit(1); });