// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// OpenZeppelin v4 imports
// ============================================================
// ERC721: Provides the standard interface for Non-Fungible Tokens (NFTs).
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
// Ownable: Provides basic access control, ensuring only the deployer/custodian can call specific functions.
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title  CarbonCreditNFT
 * @notice ERC-721 representing one verified 1-tonne carbon credit.
 *
 * @dev The `issueCredit()` function requires a `registryRetirementHash`
 * (bytes32) emitted by the off-chain registry API upon credit retirement.
 * This establishes a cryptographic two-phase link between the off-chain registry 
 * and the on-chain asset. 
 * * To prevent double-retirement and replay attacks, the hash is stored 
 * and marked as used. Any subsequent attempts to mint using the same 
 * hash will revert.
 */
contract CarbonCreditNFT is ERC721, Ownable {

    // ── State ───────────────────────────────────────────────────────────────

    /// @notice A counter to track the ID of the next minted NFT. Starts at 0.
    uint256 public nextTokenId;

    /// @notice Maps a specific on-chain token ID back to the off-chain registry retirement hash.
    /// @dev Public visibility automatically generates a getter function for this mapping.
    mapping(uint256 => bytes32) public tokenRetirementHash;

    /// @notice Tracks used retirement hashes to prevent the same credit from being minted twice.
    mapping(bytes32 => bool) public usedRetirementHashes;

    // ── Custom errors ────────────────────────────────────────────────────────
    // Custom errors are used instead of string messages to save deployment and execution gas.

    /// @dev Reverts when the same registryRetirementHash is submitted more than once.
    error AlreadyRetired();

    /// @dev Reverts when an empty or zero-value hash (bytes32(0)) is submitted.
    error InvalidRetirementHash();

    // ── Events ───────────────────────────────────────────────────────────────

    /**
     * @notice Emitted when a new token is linked to a registry retirement record.
     * @dev Indexed parameters allow off-chain applications to filter and search these events easily.
     * @param tokenId        The newly minted ERC-721 token ID.
     * @param retirementHash The bytes32 hash received from the registry API.
     */
    event RegistryRetirementLinked(uint256 indexed tokenId, bytes32 indexed retirementHash);

    // ── Constructor ──────────────────────────────────────────────────────────

    /**
     * @notice Initializes the contract by setting a name and symbol for the NFT collection.
     * @dev Sets the initial owner of the contract to the deployer address via Ownable(msg.sender).
     */
    constructor() ERC721("Verra Carbon Tonne", "VCT") Ownable(msg.sender) {}

    // ── Core function ────────────────────────────────────────────────────────

    /**
     * @notice Issue a new 1-tonne carbon credit NFT linked to a registry retirement.
     *
     * @dev    The caller must supply the `registryRetirementHash` that was produced
     * by the registry's off-chain API when it retired the credit. The hash
     * is stored immutably and flagged as used to prevent replay.
     *
     * @param  registryRetirementHash  A non-zero bytes32 identifier emitted by
     * the verified registry upon credit retirement.
     * @return tokenId                 The newly minted ERC-721 token ID.
     *
     * Requirements:
     * - Caller must be the contract owner (authorised custodian / bridge operator).
     * - `registryRetirementHash` must not be bytes32(0).
     * - `registryRetirementHash` must not have been used in a prior call.
     */
    function issueCredit(bytes32 registryRetirementHash)
        external
        onlyOwner
        returns (uint256 tokenId)
    {
        // Security Guard 1: Reject empty hashes to prevent accidental blank mints.
        if (registryRetirementHash == bytes32(0)) {
            revert InvalidRetirementHash();
        }

        // Security Guard 2: Anti-replay protection. Check if the hash was already mapped to a token.
        if (usedRetirementHashes[registryRetirementHash]) {
            revert AlreadyRetired();
        }

        // State Update 1: Mark this exact registry hash as consumed so it can never be used again.
        usedRetirementHashes[registryRetirementHash] = true;

        // State Update 2: Assign the current counter value to the new token, then increment the counter.
        tokenId = nextTokenId++;
        
        // Interaction: Safely create the NFT and assign ownership to the caller (custodian).
        _mint(msg.sender, tokenId);

        // State Update 3: Permanently bind the off-chain registry record to this specific on-chain token.
        tokenRetirementHash[tokenId] = registryRetirementHash;

        // Log the successful linkage to the blockchain for transparency and auditability.
        emit RegistryRetirementLinked(tokenId, registryRetirementHash);
    }
}