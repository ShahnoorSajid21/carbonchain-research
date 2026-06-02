// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// OpenZeppelin v4 imports
// ============================================================
// ERC20: Provides the standard interface for fungible tokens.
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
// AccessControl: Provides granular, role-based security permissions.
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title  CarbonMicroToken (CKG – Carbon Kilogram Token)
 * @notice ERC-20 token representing 1 kg of CO₂e. 1,000 CKG ≙ one 1-tonne credit NFT.
 *
 * @dev This contract uses OpenZeppelin AccessControl to prevent centralization risks.
 * It implements two distinct roles:
 *
 * 1. MINTER_ROLE: Granted exclusively to the CarbonVault contract. 
 * Required to mint new fractions and burn them during retirement.
 * 2. GOVERNANCE_ROLE: Granted to a multisig address (e.g., a Gnosis Safe).
 * Required to execute `updateVault()` if the bridge contract needs an upgrade.
 *
 * The `retireAndBurn()` function produces a structured, immutable compliance 
 * record on-chain, acting as the cryptographic proof of offset for the SME.
 */
contract CarbonMicroToken is ERC20, AccessControl {

    // ── Roles ────────────────────────────────────────────────────────────────

    /// @notice Role required to mint and burn tokens (granted exclusively to the vault).
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /// @notice Role required to update the vault address (granted to governance multisig).
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    // ── State ────────────────────────────────────────────────────────────────

    /// @notice Address of the current active vault contract (the sole MINTER_ROLE holder).
    address public vault;

    // ── Custom errors ────────────────────────────────────────────────────────

    /// @dev Thrown when updateVault() is called with the zero address to prevent locking the protocol.
    error InvalidVaultAddress();

    // ── Events ───────────────────────────────────────────────────────────────

    /**
     * @notice Structured, immutable on-chain compliance record for carbon retirement.
     * @dev    This event acts as the final offset certificate for the SME.
     *
     * @param retiree             Address of the SME that retired the tokens.
     * @param amountKg            Number of whole kilograms retired.
     * @param timestamp           block.timestamp at the exact time of retirement.
     * @param blockNumber         block.number (acts as a cross-chain verification anchor).
     * @param complianceReference Optional bytes32 reference to an off-chain ESG/audit report. 
     * Defaults to bytes32(0) if not provided.
     */
    event CarbonRetired(
        address indexed retiree,
        uint256 amountKg,
        uint256 timestamp,
        uint256 blockNumber,
        bytes32 complianceReference
    );

    /**
     * @notice Emitted when governance rotates the vault address.
     * @param oldVault The address of the previous vault that lost minting privileges.
     * @param newVault The address of the new vault that gained minting privileges.
     */
    event VaultUpdated(address indexed oldVault, address indexed newVault);

    // ── Constructor ──────────────────────────────────────────────────────────

    /**
     * @notice Initializes the CKG token and sets up the security roles.
     * * @param vaultAddress      Address of the CarbonVault contract (receives MINTER_ROLE).
     * @param governanceAddress Address of the multisig that holds GOVERNANCE_ROLE.
     *
     * @dev On deployment:
     * - DEFAULT_ADMIN_ROLE -> Deployer (serves as an emergency safety backstop).
     * - GOVERNANCE_ROLE    -> Assigned to the governanceAddress.
     * - MINTER_ROLE        -> Assigned to the vaultAddress.
     */
    constructor(address vaultAddress, address governanceAddress)
        ERC20("Carbon Kilogram Token", "CKG")
    {
        require(vaultAddress != address(0), "Vault cannot be zero address");
        require(governanceAddress != address(0), "Governance cannot be zero address");

        vault = vaultAddress;

        // Grant roles — standard AccessControl RoleGranted events are emitted automatically
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GOVERNANCE_ROLE, governanceAddress);
        _grantRole(MINTER_ROLE, vaultAddress);
    }

    // ── Vault management (GOVERNANCE_ROLE only) ──────────────────────────────

    /**
     * @notice Rotate the vault address in the event of a protocol upgrade.
     *
     * @dev    Revokes MINTER_ROLE from the old vault and grants it to the new one.
     * This ensures only one contract can ever mint tokens at a time.
     * Only callable by an account holding the GOVERNANCE_ROLE.
     *
     * @param  newVault Address of the replacement CarbonVault contract.
     */
    function updateVault(address newVault)
        external
        onlyRole(GOVERNANCE_ROLE)
    {
        // Security Guard: Prevent accidental protocol bricking
        if (newVault == address(0)) revert InvalidVaultAddress();

        address oldVault = vault;
        vault = newVault;

        // Security Update: Swap the minting roles safely
        _revokeRole(MINTER_ROLE, oldVault);
        _grantRole(MINTER_ROLE, newVault);

        emit VaultUpdated(oldVault, newVault);
    }

    // ── Token operations (MINTER_ROLE only) ─────────────────────────────────

    /**
     * @notice Mint CKG tokens to a recipient.
     * @dev    Can only be called by the active CarbonVault contract.
     * @param  to     Recipient address (the SME buyer).
     * @param  amount Token amount in base unit decimals (kg × 10^18).
     */
    function mint(address to, uint256 amount)
        external
        onlyRole(MINTER_ROLE)
    {
        _mint(to, amount);
    }

    /**
     * @notice Burn CKG tokens from an account without triggering a compliance event.
     * @dev    Called by CarbonVault when a depositor reclaims their original 1-Tonne NFT.
     * @param  from   Account to burn tokens from.
     * @param  amount Token amount in base unit decimals (kg × 10^18).
     */
    function burn(address from, uint256 amount)
        external
        onlyRole(MINTER_ROLE)
    {
        _burn(from, amount);
    }

    /**
     * @notice Permanently retire tokens and emit the structured compliance record.
     *
     * @dev    Called exclusively by `CarbonVault.retireCarbon()`.
     * Mathematically converts the whole `amountKg` into the correct base 18 decimals,
     * burns the tokens to remove them from supply, and logs the metadata.
     *
     * @param  retiree             The SME address performing the retirement.
     * @param  amountKg            The exact number of whole kilograms to retire.
     * @param  complianceReference Optional bytes32 link to an off-chain ESG record.
     */
    function retireAndBurn(
        address retiree,
        uint256 amountKg,
        bytes32 complianceReference
    )
        external
        onlyRole(MINTER_ROLE)
    {
        // Math Calculation: Convert whole Kg to base token decimal units (10^18)
        uint256 burnAmount = amountKg * (10 ** decimals());

        // Security Guard: Ensure the retiree actually holds enough tokens to cover the burn
        require(
            balanceOf(retiree) >= burnAmount,
            "Insufficient Fractional Balance"
        );

        // State Update: Permanently destroy the tokens
        _burn(retiree, burnAmount);

        // Interaction: Emit the immutable audit proof to the blockchain
        emit CarbonRetired(
            retiree,
            amountKg,
            block.timestamp,
            block.number,
            complianceReference
        );
    }
}