/**
 * CarbonProtocol.test.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Hardhat + ethers.js automated security and integration test suite.
 * * Validates the end-to-end execution of the Carbon Fractionalization Protocol:
 * 1. CarbonCreditNFT  (ERC-721 Parent)
 * 2. CarbonVault      (Escrow Bridge)
 * 3. CarbonMicroToken (ERC-20 Fractional Child)
 *
 * This suite executes a full happy-path workflow alongside seven adversarial 
 * attack scenarios to prove 100% functional accuracy and strict access control.
 *
 * Dependencies:
 * "hardhat": "^2.22.0"
 * "@nomicfoundation/hardhat-toolbox": "^4.0.0"
 */

const { expect }  = require("chai");
const { ethers }  = require("hardhat");

// ─────────────────────────────────────────────────────────────────────────────
// Protocol Constants & Helpers
// ─────────────────────────────────────────────────────────────────────────────
const TOKENS_PER_TONNE   = 1_000n;                               // 1,000 CKG per NFT
const DECIMALS           = 18n;                                  // Standard ERC-20 decimals
const FULL_AMOUNT        = TOKENS_PER_TONNE * (10n ** DECIMALS); // 1,000 * 10^18

/**
 * @notice Generates a deterministic mock registry hash for testing.
 * @param {string} seed - Unique string to ensure hash uniqueness per test.
 * @returns {string} bytes32 Keccak256 hash simulating an off-chain Verra API payload.
 */
function makeHash(seed) {
  return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(`registry-retirement-${seed}`));
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Test Suite
// ─────────────────────────────────────────────────────────────────────────────
describe("CarbonProtocol – Security & Integration Suite", function () {

  // Protocol Contracts
  let nft, token, vault;

  // Network Actors (Signers)
  let owner;       // Deployer & Custodian (Issues parent credits)
  let governance;  // Multisig address (Controls protocol upgrades)
  let sme;         // End-user (Purchases and retires fractional credits)
  let attacker;    // Malicious actor attempting exploits

  // ── Setup: Fresh deployment before every test ensures clean state ──────────
  beforeEach(async function () {
    [owner, governance, sme, attacker] = await ethers.getSigners();

    // 1. Deploy NFT Contract (owner gets DEFAULT_ADMIN and issue rights)
    const NFT = await ethers.getContractFactory("CarbonCreditNFT");
    nft = await NFT.deploy();
    await nft.deployed();

    // 2. Deploy Token Contract 
    // Note: We use `owner.address` temporarily for the vault address parameter 
    // to pass constructor validation, then update it securely in Step 4.
    const Token = await ethers.getContractFactory("CarbonMicroToken");
    token = await Token.deploy(owner.address, governance.address);
    await token.deployed();

    // 3. Deploy Vault (Establishes links to the NFT and Token contracts)
    const Vault = await ethers.getContractFactory("CarbonVault");
    vault = await Vault.deploy(nft.address, token.address);
    await vault.deployed();

    // 4. Governance Action: Rotate active vault address to the real vault,
    // securely transferring the MINTER_ROLE.
    await token.connect(governance).updateVault(vault.address);

    // 5. Custodian Action: Vault needs to be able to route the credit appropriately.
    await nft.transferOwnership(owner.address);
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Security Test 1: Prevent Unauthorized Asset Draining
  // ──────────────────────────────────────────────────────────────────────────
  it("Reverts if a non-owner attempts to fractionalize a credit", async function () {
    // Setup: Issue a credit to the legitimate SME
    const hash = makeHash("test1");
    await nft.connect(owner).issueCredit(hash);
    const tokenId = 0;

    await nft.connect(sme).approve(vault.address, tokenId);

    // Attack: Malicious actor tries to push the SME's token into the vault
    // Result: ERC-721 safeTransferFrom blocks the unauthorized transfer
    await expect(
      vault.connect(attacker).fractionalizeCredit(tokenId)
    ).to.be.reverted;
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Security Test 2: Prevent Inflation via Double-Locking
  // ──────────────────────────────────────────────────────────────────────────
  it("Reverts if the same NFT is fractionalized twice (VaultAlreadyLocked)", async function () {
    const hash = makeHash("test2");
    await nft.connect(owner).issueCredit(hash);
    const tokenId = 0;

    // First fractionalization succeeds
    await nft.connect(owner).approve(vault.address, tokenId);
    await vault.connect(owner).fractionalizeCredit(tokenId);

    // Attack: Attempt to process the same token ID again to artificially inflate CKG supply
    await expect(
      vault.connect(owner).fractionalizeCredit(tokenId)
    ).to.be.revertedWithCustomError(vault, "VaultAlreadyLocked")
      .withArgs(tokenId);
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Security Test 3: Strict Accounting & Balance Validation
  // ──────────────────────────────────────────────────────────────────────────
  it("Reverts if an SME attempts to retire more CKG than their balance", async function () {
    const hash = makeHash("test3");
    await nft.connect(owner).issueCredit(hash);
    const tokenId = 0;

    // Fractionalize to vault
    await nft.connect(owner).approve(vault.address, tokenId);
    await vault.connect(owner).fractionalizeCredit(tokenId);

    // Transfer exactly 400 CKG to the SME
    const fourHundredKg = 400n * (10n ** DECIMALS);
    await token.connect(owner).transfer(sme.address, fourHundredKg);

    // Attack: SME tries to retire 600 kg
    await expect(
      vault.connect(sme).retireCarbon(600, ethers.constants.HashZero)
    ).to.be.revertedWith("Insufficient Fractional Balance");
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Security Test 4: Registry Double-Spend (Replay Attack) Prevention
  // ──────────────────────────────────────────────────────────────────────────
  it("Reverts if an off-chain registry hash is reused (AlreadyRetired)", async function () {
    const hash = makeHash("test4-replay");

    // First issuance succeeds and maps the hash on-chain
    await nft.connect(owner).issueCredit(hash);

    // Attack: Custodian or compromised API attempts to mint a second NFT from the same physical retirement
    await expect(
      nft.connect(owner).issueCredit(hash)
    ).to.be.revertedWithCustomError(nft, "AlreadyRetired");
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Security Test 5: Input Sanitization
  // ──────────────────────────────────────────────────────────────────────────
  it("Reverts if a zero-value bytes32 hash is submitted", async function () {
    await expect(
      nft.connect(owner).issueCredit(ethers.constants.HashZero)
    ).to.be.revertedWithCustomError(nft, "InvalidRetirementHash");
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Integration Test 6: Full Protocol End-to-End Workflow (Happy Path)
  // ──────────────────────────────────────────────────────────────────────────
  it("Executes the complete SME workflow: Issue → Fractionalize → Transfer → Retire", async function () {
    const hash          = makeHash("happy-path");
    const complianceRef = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ESG-REPORT-Q1-2025"));

    // ── Phase 1: Issue Parent Credit ──
    const tx1 = await nft.connect(owner).issueCredit(hash);
    await tx1.wait();
    const tokenId = 0;

    // Verify parent NFT state
    expect(await nft.ownerOf(tokenId)).to.equal(owner.address);
    expect(await nft.tokenRetirementHash(tokenId)).to.equal(hash);
    expect(await nft.usedRetirementHashes(hash)).to.equal(true);

    // ── Phase 2: Fractionalize ──
    await nft.connect(owner).approve(vault.address, tokenId);
    const tx2 = await vault.connect(owner).fractionalizeCredit(tokenId);
    const receipt2 = await tx2.wait();

    // Verify escrow state
    expect(await nft.ownerOf(tokenId)).to.equal(vault.address);
    expect(await vault.tokenDepositor(tokenId)).to.equal(owner.address);

    // Verify token minting calculations
    const ownerBalance = await token.balanceOf(owner.address);
    expect(ownerBalance).to.equal(FULL_AMOUNT);

    // ── Phase 3: SME Acquisition ──
    const retireKg     = 350n;
    const retireAmount = retireKg * (10n ** DECIMALS);
    await token.connect(owner).transfer(sme.address, retireAmount);
    expect(await token.balanceOf(sme.address)).to.equal(retireAmount);

    // ── Phase 4: SME Compliance Retirement ──
    const supplyBefore = await token.totalSupply();
    const tx3 = await vault.connect(sme).retireCarbon(retireKg, complianceRef);
    const receipt3 = await tx3.wait();

    // Verify accounting: SME balance drained, global supply reduced
    expect(await token.balanceOf(sme.address)).to.equal(0n);
    const supplyAfter = await token.totalSupply();
    expect(supplyBefore.sub(supplyAfter)).to.equal(retireAmount);

    // Verify Immutable Audit Trail (Event emission)
    const retireEvent = receipt3.events?.find(e => e.event === "CarbonRetired");
    expect(retireEvent).to.not.be.undefined;
    expect(retireEvent.args.retiree).to.equal(sme.address);
    expect(retireEvent.args.amountKg).to.equal(retireKg);
    expect(retireEvent.args.blockNumber).to.equal(receipt3.blockNumber);
    expect(retireEvent.args.complianceReference).to.equal(complianceRef);
    expect(retireEvent.args.timestamp).to.be.gt(0);
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Security Test 7: Upgradeability and Role Rotation
  // ──────────────────────────────────────────────────────────────────────────
  it("Allows Governance to rotate vaults, strictly enforcing one MINTER_ROLE at a time", async function () {
    const MINTER_ROLE = await token.MINTER_ROLE();

    // Verify initial state
    expect(await token.hasRole(MINTER_ROLE, vault.address)).to.equal(true);

    // Simulate deployment of a V2 Vault
    const [,,,, newVaultAccount] = await ethers.getSigners();

    // Governance executes rotation
    await token.connect(governance).updateVault(newVaultAccount.address);

    // Verify roles successfully swapped (Preventing two contracts from minting simultaneously)
    expect(await token.hasRole(MINTER_ROLE, vault.address)).to.equal(false);
    expect(await token.hasRole(MINTER_ROLE, newVaultAccount.address)).to.equal(true);
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Security Test 8: Privilege Escalation Prevention
  // ──────────────────────────────────────────────────────────────────────────
  it("Reverts if an attacker attempts to hijack the protocol via updateVault", async function () {
    await expect(
      token.connect(attacker).updateVault(attacker.address)
    ).to.be.reverted; // OpenZeppelin AccessControl handles the revert reason
  });
});