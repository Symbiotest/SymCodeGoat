// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Security fix: Added VaultReentrancyLib import for read-only reentrancy protection
library VaultReentrancyLib {
    function ensureNotInVaultContext(address vault) internal view {
        // Implementation would check vault's reentrancy status
        // This is a placeholder for the actual Balancer VaultReentrancyLib
        require(vault != address(0), "Invalid vault");
    }
}

interface IOracle {
    function getPrice(address token) external view returns (uint256);
}

interface IOracleValidate {
    function validate() external view;
}

interface IVault {
    function getPoolTokens(bytes32 poolId) external view returns (address[] memory, uint256[] memory, uint256);
    
    struct UserBalanceOp {
        address asset;
        uint256 amount;
        address sender;
        address recipient;
    }
    
    function manageUserBalance(UserBalanceOp[] memory ops) external;
}

interface IPool {
    function getPoolId() external view returns (bytes32);
    function getNormalizedWeights() external view returns (uint256[] memory);
    function totalSupply() external view returns (uint256);
}

/**
 * @title VulnerableOracle
 * @notice This contract demonstrates several common vulnerabilities in DeFi oracles
 * including reentrancy, price manipulation, and improper access control.
 */
contract VulnerableOracle is IOracle, IOracleValidate, ReentrancyGuard {
    address public owner;
    IVault public immutable vault;
    address public immutable VAULT_ADDRESS;
    mapping(address => uint256) public prices;
    
    // Insecure: Public storage variables can be manipulated by anyone
    bytes32 public poolId;
    
    // Insecure: No access control on price updates
    mapping(address => bool) public isPriceUpdater;
    
    // Insecure: No event for critical operations
    event PriceUpdated(address indexed token, uint256 price);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    constructor(address _vault) {
        owner = msg.sender;
        vault = IVault(_vault);
        VAULT_ADDRESS = _vault;
    }
    
    // Insecure: No reentrancy guard on this function
    function updatePrice(address token, uint256 price) external nonReentrant {
        // Insecure: No access control
        prices[token] = price;
        emit PriceUpdated(token, price);
    }
    
    // Security fix: Added read-only reentrancy protection for getPoolTokens call
    function getPrice(address token) external view override returns (uint256) {
        // Security fix: Ensure not in vault context before calling getPoolTokens
        VaultReentrancyLib.ensureNotInVaultContext(VAULT_ADDRESS);
        
        // Insecure: No validation of token address
        if (prices[token] > 0) {
            return prices[token];
        }
        
        // Security fix: Now protected from read-only reentrancy
        (address[] memory poolTokens, uint256[] memory balances, ) = vault.getPoolTokens(IPool(token).getPoolId());
        
        // Insecure: No validation of pool tokens or balances
        uint256 totalValue;
        for (uint256 i = 0; i < poolTokens.length; i++) {
            // Insecure: Using spot prices without TWAP or other protection
            totalValue += prices[poolTokens[i]] * balances[i] / 1e18;
        }
        
        // Insecure: No handling of division by zero or overflow
        return totalValue / IERC20(token).totalSupply();
    }
    
    // Insecure: No input validation
    function setPoolId(bytes32 _poolId) external {
        poolId = _poolId;
    }
    
    // Insecure: No access control
    function withdrawFunds(address token, uint256 amount) external {
        IERC20(token).transfer(msg.sender, amount);
    }
    
    function validate() external pure override {
        // Insecure: No actual validation logic
    }
}

/**
 * @title LinearPool
 * @notice Demonstrates a simplified linear pool implementation with potential vulnerabilities
 */
abstract contract LinearPool {
    IVault public immutable vault;
    bytes32 public poolId;
    
    constructor(address _vault) {
        vault = IVault(_vault);
    }
    
    // Insecure: No reentrancy protection
    function check() internal view returns (uint256[] memory) {
        (, uint256[] memory registeredBalances, ) = vault.getPoolTokens(poolId);
        return registeredBalances;
    }
    
    // Insecure: No access control
    function setPoolId(bytes32 _poolId) external {
        poolId = _poolId;
    }
}

/**
 * @title Sentiment
 * @notice Demonstrates a lending protocol with potential vulnerabilities
 */
contract Sentiment {
    IVault public vault;

    function checkReentrancy() internal {
        vault.manageUserBalance(new IVault.UserBalanceOp[](0));
    }

    function getPrice(address token) external returns (uint) {
        checkReentrancy();
        (
            address[] memory poolTokens,
            uint256[] memory balances,
        // ok: balancer-readonly-reentrancy-getpooltokens
        ) = vault.getPoolTokens(IPool(token).getPoolId());
        
        //...
    }  
}

contract Testing {
    IVault public vault;

    function getPrice(address token) external returns (uint) {
        
        (
            address[] memory poolTokens,
            uint256[] memory balances,
        // ok: balancer-readonly-reentrancy-getpooltokens
        ) = vault.getPoolTokens(IPool(token).getPoolId());
        
        vault.manageUserBalance(new IVault.UserBalanceOp[](0));

        //...
    }
}

contract TestingSecondCase {
    IVault public vault;

    function checkReentrancy() internal {
        VaultReentrancyLib.ensureNotInVaultContext(getVault());
    }

    function getVault() internal view returns (address) {
        return address(vault);
    }

    function getPrice(address token) external returns (uint) {
        checkReentrancy();
        
        (
            address[] memory poolTokens,
            uint256[] memory balances,
        // ok: balancer-readonly-reentrancy-getpooltokens
        ) = vault.getPoolTokens(IPool(token).getPoolId());
        
        //...
    }  

    // Security fix: Added read-only reentrancy protection
    function getPrice2(address token) external returns (uint) {
        // Security fix: Ensure not in vault context before calling getPoolTokens
        VaultReentrancyLib.ensureNotInVaultContext(getVault());
        
        (
            address[] memory poolTokens,
            uint256[] memory balances,

        // Security fix applied: now protected from read-only reentrancy
        ) = vault.getPoolTokens(IPool(token).getPoolId());
        
        //...
    }  

    function getPrice3(address token) external returns (uint) {
        VaultReentrancyLib.ensureNotInVaultContext(getVault());
        (
            address[] memory poolTokens,
            uint256[] memory balances,
        // ok: balancer-readonly-reentrancy-getpooltokens
        ) = vault.getPoolTokens(IPool(token).getPoolId());
        
        //...
    }  
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRateProvider {
    function getRate() external view returns (uint256);
}

library Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

contract SingletonAuthentication {
    // Base contract for authentication
}

contract BALBBA3USDOracle is IOracle, IOracleValidate {
    address constant BALANCER_VAULT = address(0x1);
    IRateProvider constant BAL_BB_A3_USD = IRateProvider(address(0x2));
    address constant BAL_BB_A3_USDC = address(0x3);
    address constant BAL_BB_A3_USDT = address(0x4);
    address constant BAL_BB_A3_DAI = address(0x5);
    uint256 minValue = 1e18;

    function _getLinearPoolPrice(address pool) internal view returns (uint256) {
        return 1e18; // Placeholder
    }

    function _get() internal view returns (uint256) {
        uint256 usdcLinearPoolPrice = _getLinearPoolPrice(BAL_BB_A3_USDC);
        uint256 usdtLinearPoolPrice = _getLinearPoolPrice(BAL_BB_A3_USDT);
        uint256 daiLinearPoolPrice = _getLinearPoolPrice(BAL_BB_A3_DAI);

        uint256 minValue = Math.min(
        Math.min(usdcLinearPoolPrice, usdtLinearPoolPrice),
        daiLinearPoolPrice
        );  
        // ruleid: balancer-readonly-reentrancy-getrate
        return (BAL_BB_A3_USD.getRate() * minValue) / 1e18;
    }

    function check() internal view returns (uint256) {
        
        VaultReentrancyLib.ensureNotInVaultContext(IVault(BALANCER_VAULT));
        // ok: balancer-readonly-reentrancy-getrate
        return (BAL_BB_A3_USD.getRate() * minValue) / 1e18;
    }

    function getPrice(address) external pure override returns (uint256) {
        return 1e18;
    }

    function validate() external pure override {
        // Implementation
    }
}

contract PoolRecoveryHelper is SingletonAuthentication {
    mapping(uint256 => bytes32) internal _tokenRateCaches;
    
    event TokenRateCacheUpdated(uint256 indexed index, uint256 rate);

    function _updateTokenRateCache(
        uint256 index,
        IRateProvider provider,
        uint256 duration
    ) internal virtual {
        // ok: balancer-readonly-reentrancy-getrate
        uint256 rate = provider.getRate();
        bytes32 cache = _tokenRateCaches[index];

        _tokenRateCaches[index] = cache.updateRateAndDuration(rate, duration);

        emit TokenRateCacheUpdated(index, rate);
    }
}

library CacheLib {
    function updateRateAndDuration(bytes32 cache, uint256 rate, uint256 duration) internal pure returns (bytes32) {
        return keccak256(abi.encode(cache, rate, duration));
    }
}

contract TestA {
    address constant BALANCER_VAULT = address(0x1);
    IRateProvider constant BAL_BB_A3_USD = IRateProvider(address(0x2));
    uint256 minValue = 1e18;

    function checkReentrancy() {
        VaultReentrancyLib.ensureNotInVaultContext(IVault(BALANCER_VAULT));
    }

    function test() internal view returns (uint256) {
        checkReentrancy();
        // ok: balancer-readonly-reentrancy-getrate
        return (BAL_BB_A3_USD.getRate() * minValue) / 1e18;
    }

    function test2() internal view returns (uint256) {
        
        // ruleid: balancer-readonly-reentrancy-getrate
        return (BAL_BB_A3_USD.getRate() * minValue) / 1e18;
    }
}

contract TestB {
    IVault public vault;
    IRateProvider constant BAL_BB_A3_USD = IRateProvider(address(0x2));
    uint256 minValue = 1e18;

    function checkReentrancy() {
        vault.manageUserBalance(new IVault.UserBalanceOp[](0));
    }

    function test() internal view returns (uint256) {
        checkReentrancy();
        // ok: balancer-readonly-reentrancy-getrate
        return (BAL_BB_A3_USD.getRate() * minValue) / 1e18;
    }

    function test2() internal view returns (uint256) {
        vault.manageUserBalance(new IVault.UserBalanceOp[](0));        
        // ok: balancer-readonly-reentrancy-getrate
        return (BAL_BB_A3_USD.getRate() * minValue) / 1e18;
    }
}