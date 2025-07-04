const hre = require("hardhat");
const fs = require("fs");
const path = require("path"); // Make sure to require 'path'

async function main() {
  console.log("Deploying AuditRootStorage contract...");
  const Contract = await hre.ethers.getContractFactory("AuditRootStorage");
  const contract = await Contract.deploy();
  await contract.waitForDeployment();
  
  const contractAddress = await contract.getAddress();
  console.log("✅ Contract deployed to:", contractAddress);

  const deploymentInfo = {
    contractAddress: contractAddress,
    network: hre.network.name,
  };

  // Use path.join to create a full, unambiguous path to the project's root folder
  const outputPath = path.join(__dirname, '..', 'deployment-info.json');
  fs.writeFileSync(outputPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`✅ Deployment info saved to ${outputPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});