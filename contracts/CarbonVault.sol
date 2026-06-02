// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// OpenZeppelin v4 imports
// ============================================================
// ERC721Holder: Allows this contract to safely receive and hold ERC-721 tokens.
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
// ReentrancyGuard: Provides the nonReentrant modifier to prevent re-entrancy attacks during external calls.
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
// Ownable: Provides basic access control for deployment and setup.
import "@openzeppelin/contracts/access/Ownable.sol";

// Local imports (Make sure your file names match these clean versions)
import "./CarbonCreditNFT.sol";
import "./CarbonMicroToken.sol";

/**
 * @title  CarbonVault
 * @notice Tokenisation bridge: locks a 1-tonne ERC-721 NFT and mints
 * 1,000 × CKG (ERC-20, kg-scale) fractional tokens.
 *
 * @dev This contract acts as the secure custodian for the underlying carbon credits.
 * It utilizes the Checks-Effects-Interactions pattern and OpenZeppelin's 
 * ReentrancyGuard to prevent malicious actors from draining assets during 
 * the bridging process.
 * * It strictly tracks depositors via the `tokenDepositor` mapping to ensure 
 * that only the original depositor of an NFT can withdraw it, preventing 
 * fractional-consolidation attacks.
 */
contract CarbonVault is ERC721Holder, ReentrancyGuard, Ownable {

    // ── Immutable references ─────────────────────────────────────────────────

    /// @notice The contract address of the parent ERC-721 carbon credits.
    CarbonCreditNFT public immutable parentNFT;
    
    /// @notice The contract address of the fractional ERC-20 kilogram tokens.
    CarbonMicroToken public immutable childToken;

    /// @notice Tokens minted per 1-tonne NFT (1,000 kg-scale units).
    uint256 public constant TOKENS_PER_TONNE = 1_000;

    // ── State ────────────────────────────────────────────────────────────────

    /// @notice Maps tokenId → address that deposited it into the vault.
    /// @dev    A zero address (address(0)) means the token is not currently locked here.
    mapping(uint256 => address) public tokenDepositor;

    // ── Custom errors ────────────────────────────────────────────────────────

    /// @dev Thrown when fractionalizeCredit() is called for an NFT that is already vaulted.
    error VaultAlreadyLocked(uint256 tokenId);

    /// @dev Thrown when a non-depositor tries to withdraw a token they do not own.
    error NotDepositor(uint256 tokenId);

    /// @dev Thrown when the caller has insufficient CKG to redeem the underlying NFT.
    error InsufficientFractionalBalance(uint256 required, uint256 actual);

    // ── Events ───────────────────────────────────────────────────────────────

    /// @notice Emitted when a 1-Tonne NFT is safely locked and fractionalized.
    event FractionalizationComplete(
        uint256 indexed nftId,
        address indexed depositor,
        uint256 microTokensMinted
    );

    /// @notice Emitted when a depositor reclaims their NFT by returning all fractions.
    event CreditWithdrawn(
        uint256 indexed nftId,
        address indexed depositor
    );

    // ── Constructor ──────────────────────────────────────────────────────────

    /**
     * @notice Initializes the Vault and sets immutable references to the parent and child tokens.
     * @param _nftAddress   Address of the deployed CarbonCreditNFT contract.
     * @param _tokenAddress Address of the deployed CarbonMicroToken contract.
     */
    constructor(address _nftAddress, address _tokenAddress)
        Ownable(msg.sender)
    {
        parentNFT  = CarbonCreditNFT(_nftAddress);
        childToken = CarbonMicroToken(_tokenAddress);
    }

    // ── Core functions ───────────────────────────────────────────────────────

    /**
     * @notice Fractionalize a 1-tonne NFT into 1,000 CKG tokens.
     *
     * @dev    Caller must have approved this contract to transfer the NFT before calling.
     * Uses `nonReentrant` to prevent re-entrancy during the ERC-721 safeTransferFrom
     * and subsequent ERC-20 mint calls.
     *
     * @param  nftId  The ERC-721 token ID to lock and fractionalize.
     *
     * Requirements:
     * - NFT must not already be locked in this vault (VaultAlreadyLocked guard).
     * - Caller must own or be approved for the NFT.
     */
    function fractionalizeCredit(uint256 nftId)
        external
        nonReentrant
    {
        // Security Guard: Prevent double-locking or overriding an existing depositor
        if (tokenDepositor[nftId] != address(0)) {
            revert VaultAlreadyLocked(nftId);
        }

        // State Update (Checks-Effects-Interactions): Record depositor BEFORE external calls
        tokenDepositor[nftId] = msg.sender;

        // Interaction 1: Transfer NFT into vault custody
        parentNFT.safeTransferFrom(msg.sender, address(this), nftId);

        // Math Calculation: Compute mint amount using ERC-20 base decimals (1,000 * 10^18)
        uint256 microAmount = TOKENS_PER_TONNE * (10 ** childToken.decimals());

        // Interaction 2: Mint fractional tokens directly to the depositor's wallet
        childToken.mint(msg.sender, microAmount);

        emit FractionalizationComplete(nftId, msg.sender, microAmount);
    }

    /**
     * @notice Redeem a locked NFT by returning all 1,000 CKG fractions.
     *
     * @dev    The caller must hold the full fractional supply for this NFT
     * (TOKENS_PER_TONNE × 10^decimals). All fractions are burned
     * atomically before the NFT is transferred back.
     *
     * @param  nftId  The ERC-721 token ID to reclaim.
     *
     * Requirements:
     * - Caller must be the original depositor.
     * - Caller must hold the full fractional amount (1,000 CKG).
     */
    function withdrawCredit(uint256 nftId)
        external
        nonReentrant
    {
        // Security Guard 1: Only the original depositor may withdraw the NFT
        if (tokenDepositor[nftId] != msg.sender) {
            revert NotDepositor(nftId);
        }

        uint256 fullAmount = TOKENS_PER_TONNE * (10 ** childToken.decimals());
        uint256 callerBalance = childToken.balanceOf(msg.sender);

        // Security Guard 2: Ensure caller has the funds to back the withdrawal
        if (callerBalance < fullAmount) {
            revert InsufficientFractionalBalance(fullAmount, callerBalance);
        }

        // State Update: Clear depositor record BEFORE external calls
        tokenDepositor[nftId] = address(0);

        // Interaction 1: Burn the fractions from the caller's wallet
        childToken.burn(msg.sender, fullAmount);

        // Interaction 2: Return the original NFT to the depositor
        parentNFT.safeTransferFrom(address(this), msg.sender, nftId);

        emit CreditWithdrawn(nftId, msg.sender);
    }

    /**
     * @notice Permanently retire CKG tokens to create an SME compliance record.
     *
     * @dev    Retirement mechanics and event emission are delegated to the 
     * CarbonMicroToken contract to ensure the compliance record is 
     * bound to the fungible asset ledger.
     *
     * @param  kgAmount            Amount in whole kilograms to retire.
     * @param  complianceReference Optional bytes32 reference linking this
     * retirement to an off-chain ESG report.
     * Pass bytes32(0) if not required.
     *
     * Requirements:
     * - Caller must hold at least kgAmount × 10^decimals CKG tokens.
     */
    function retireCarbon(uint256 kgAmount, bytes32 complianceReference)
        external
        nonReentrant
    {
        uint256 burnAmount = kgAmount * (10 ** childToken.decimals());

        // Security Guard: Pre-check balance to provide a clear error message before delegation
        require(
            childToken.balanceOf(msg.sender) >= burnAmount,
            "Insufficient Fractional Balance"
        );

        // Interaction: Delegate burn and immutable event emission to the token contract
        childToken.retireAndBurn(msg.sender, kgAmount, complianceReference);
    }
}