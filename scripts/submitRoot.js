const hre = require("hardhat");
const fs = require("fs");

// --- CONFIGURATION ---
// PASTE YOUR DEPLOYED CONTRACT ADDRESS HERE
const CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"; 

async function main() {
  // THE ONLY CHANGE IS ON THE NEXT LINE: Update the file path
  console.log("Reading audit data from ./audit_output/audit_data.json...");
  const auditData = JSON.parse(fs.readFileSync("./audit_output/audit_data.json", "utf8"));
  
  const { companyId, weekId, merkleRoot } = auditData;
  console.log(`   -> Company: ${companyId}`);
  console.log(`   -> Week: ${weekId}`);
  console.log(`   -> Merkle Root: ${merkleRoot}`);

  if (!CONTRACT_ADDRESS || CONTRACT_ADDRESS.includes("YOUR_DEPLOYED")) {
    console.error("❌ Error: Please paste your deployed contract address into scripts/submitRoot.js");
    return;
  }

  // Get the deployer's wallet (signer)
  const [signer] = await hre.ethers.getSigners();
  console.log(`\nConnecting to contract at: ${CONTRACT_ADDRESS} with signer: ${signer.address}`);

  // Get the contract's ABI (instruction manual)
  const contractFactory = await hre.ethers.getContractFactory("AuditRootStorage");

  // Create the contract instance
  const contract = new hre.ethers.Contract(CONTRACT_ADDRESS, contractFactory.interface, signer);

  console.log("Submitting Merkle Root to the blockchain...");
  const tx = await contract.storeRoot(companyId, weekId, merkleRoot);
  
  console.log("   -> Transaction sent. Waiting for confirmation...");
  await tx.wait();
  
  console.log("✅ Transaction confirmed!");
  console.log("   -> TX Hash:", tx.hash);

  console.log("\nVerifying data on-chain...");
  const [storedRoot, timestamp] = await contract.getRoot(companyId, weekId);
  console.log(`   -> Stored Root: ${storedRoot}`);
  
  if (storedRoot === merkleRoot) {
    console.log("✅ SUCCESS: The Merkle Root has been successfully stored and verified on the blockchain.");
  } else {
    console.error("❌ FAILURE: The stored root does not match the local root.");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});