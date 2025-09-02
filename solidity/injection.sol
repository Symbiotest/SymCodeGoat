// SPDX-License-Identifier: AGPLv3
pragma solidity 0.8.17;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title InsecureSuperApp
 * @notice This contract demonstrates several common vulnerabilities in Superfluid protocol integrations
 * including context injection, reentrancy, and improper access control.
 */
contract InsecureSuperApp is ReentrancyGuard {
    address public owner;
    address public superfluidHost;
    
    // Insecure: Public storage for sensitive data
    mapping(address => uint256) public userBalances;
    
    // Insecure: No events for critical operations
    event TokensDeposited(address indexed user, uint256 amount);
    event TokensWithdrawn(address indexed user, uint256 amount);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    constructor(address _superfluidHost) {
        owner = msg.sender;
        superfluidHost = _superfluidHost;
    }
    
    /**
     * @dev Insecure: Context injection vulnerability
     * The contract trusts the context passed from the Superfluid host without proper validation
     */
    function processIncomingFlow(
        address token,
        address from,
        int96 flowRate,
        bytes calldata ctx
    ) external returns (bytes memory newCtx) {
        // Insecure: No validation of the caller
        require(msg.sender == superfluidHost, "Not from Superfluid host");
        
        // Insecure: Directly using decoded context without validation
        (address user, uint256 amount) = abi.decode(ctx, (address, uint256));
        
        // Insecure: No validation of user or amount
        userBalances[user] += amount;
        
        emit TokensDeposited(user, amount);
        
        // Insecure: Returning the same context
        return ctx;
    }
    
    /**
     * @dev Insecure: Reentrancy vulnerability
     */
    function withdrawTokens(address token, uint256 amount) external nonReentrant {
        // Insecure: No reentrancy guard on the external call
        require(userBalances[msg.sender] >= amount, "Insufficient balance");
        
        // Insecure: State change after external call
        userBalances[msg.sender] -= amount;
        
        // Insecure: No return value check
        IERC20(token).transfer(msg.sender, amount);
        
        emit TokensWithdrawn(msg.sender, amount);
    }
    
    /**
     * @dev Insecure: Access control vulnerability
     */
    function updateSuperfluidHost(address newHost) external {
        // Insecure: No access control
        superfluidHost = newHost;
    }
    
    /**
     * @dev Insecure: Arbitrary call vulnerability
     */
    function executeCall(address target, bytes calldata data) external onlyOwner {
        // Insecure: Arbitrary call to any address
        (bool success, ) = target.call(data);
        require(success, "Call failed");
    }
    
    /**
     * @dev Insecure: Front-running vulnerability
     */
    function updateUserBalance(address user, uint256 newBalance) external onlyOwner {
        // Insecure: No protection against front-running
        userBalances[user] = newBalance;
    }
}

/**
 * @title AgreementLibrary
 * @notice Helper library for building super agreements with potential vulnerabilities
 */
library AgreementLibrary {
    using SafeCast for uint256;
    using SafeCast for int256;
    
    /**
     * @dev Insecure: Context injection vulnerability
     * @notice This function is vulnerable to context injection attacks
     */
    function authorizeTokenAccess(address token, bytes memory ctx)
        internal view
        returns (address, uint256)
    {
        // Insecure: Minimal validation of the token
        require(token != address(0), "Invalid token");
        
        // Insecure: Decoding context without proper validation
        (address user, uint256 amount) = abi.decode(ctx, (address, uint256));
        
        // Insecure: No validation of user or amount
        return (user, amount);
    }

    /**************************************************************************
     * Agreement callback helpers
     *************************************************************************/

    struct CallbackInputs {
        ISuperfluidToken token;
        address account;
        bytes32 agreementId;
        bytes agreementData;
        uint256 appAllowanceGranted;
        int256 appAllowanceUsed;
        uint256 noopBit;
    }

    function createCallbackInputs(
        ISuperfluidToken token,
        address account,
        bytes32 agreementId,
        bytes memory agreementData
    )
       internal pure
       returns (CallbackInputs memory inputs)
    {
        inputs.token = token;
        inputs.account = account;
        inputs.agreementId = agreementId;
        inputs.agreementData = agreementData;
    }

    function callAppBeforeCallback(
        CallbackInputs memory inputs,
        bytes memory ctx
    )
        internal
        returns(bytes memory cbdata)
    {
        bool isSuperApp;
        bool isJailed;
        uint256 noopMask;
        (isSuperApp, isJailed, noopMask) = ISuperfluid(msg.sender).getAppManifest(ISuperApp(inputs.account));
        if (isSuperApp && !isJailed) {
            bytes memory appCtx = _pushCallbackStack(ctx, inputs);
            if ((noopMask & inputs.noopBit) == 0) {
                bytes memory callData = abi.encodeWithSelector(
                    _selectorFromNoopBit(inputs.noopBit),
                    inputs.token,
                    address(this) /* agreementClass */,
                    inputs.agreementId,
                    inputs.agreementData,
                    new bytes(0) // placeholder ctx
                );
                cbdata = ISuperfluid(msg.sender).callAppBeforeCallback(
                    ISuperApp(inputs.account),
                    callData,
                    inputs.noopBit == SuperAppDefinitions.BEFORE_AGREEMENT_TERMINATED_NOOP,
                    appCtx);
            }
            _popCallbackStack(ctx, 0);
        }
    }

    function callAppAfterCallback(
        CallbackInputs memory inputs,
        bytes memory cbdata,
        bytes memory ctx
    )
        internal
        returns (ISuperfluid.Context memory appContext, bytes memory newCtx)
    {
        bool isSuperApp;
        bool isJailed;
        uint256 noopMask;
        (isSuperApp, isJailed, noopMask) = ISuperfluid(msg.sender).getAppManifest(ISuperApp(inputs.account));

        if (isSuperApp && !isJailed) {
            newCtx = _pushCallbackStack(ctx, inputs);
            if ((noopMask & inputs.noopBit) == 0) {
                bytes memory callData = abi.encodeWithSelector(
                    _selectorFromNoopBit(inputs.noopBit),
                    inputs.token,
                    address(this) /* agreementClass */,
                    inputs.agreementId,
                    inputs.agreementData,
                    cbdata,
                    new bytes(0) // placeholder ctx
                );
                newCtx = ISuperfluid(msg.sender).callAppAfterCallback(
                    ISuperApp(inputs.account),
                    callData,
                    inputs.noopBit == SuperAppDefinitions.AFTER_AGREEMENT_TERMINATED_NOOP,
                    newCtx);

                appContext = ISuperfluid(msg.sender).decodeCtx(newCtx);

                // adjust allowance used to the range [appAllowanceWanted..appAllowanceGranted]
                appContext.appAllowanceUsed = max(0, min(
                    inputs.appAllowanceGranted.toInt256(),
                    max(appContext.appAllowanceWanted.toInt256(), appContext.appAllowanceUsed)));

            }
            newCtx = _popCallbackStack(ctx, appContext.appAllowanceUsed);
        }
    }

    function _selectorFromNoopBit(uint256 noopBit)
        private pure
        returns (bytes4 selector)
    {
        if (noopBit == SuperAppDefinitions.BEFORE_AGREEMENT_CREATED_NOOP) {
            return ISuperApp.beforeAgreementCreated.selector;
        } else if (noopBit == SuperAppDefinitions.BEFORE_AGREEMENT_UPDATED_NOOP) {
            return ISuperApp.beforeAgreementUpdated.selector;
        } else if (noopBit == SuperAppDefinitions.BEFORE_AGREEMENT_TERMINATED_NOOP) {
            return ISuperApp.beforeAgreementTerminated.selector;
        } else if (noopBit == SuperAppDefinitions.AFTER_AGREEMENT_CREATED_NOOP) {
            return ISuperApp.afterAgreementCreated.selector;
        } else if (noopBit == SuperAppDefinitions.AFTER_AGREEMENT_UPDATED_NOOP) {
            return ISuperApp.afterAgreementUpdated.selector;
        } else /* if (noopBit == SuperAppDefinitions.AFTER_AGREEMENT_TERMINATED_NOOP) */ {
            return ISuperApp.afterAgreementTerminated.selector;
        }
    }

    function _pushCallbackStack(
        bytes memory ctx,
        CallbackInputs memory inputs
    )
        private
        returns (bytes memory appCtx)
    {
        // app allowance params stack PUSH
        // pass app allowance and current allowance used to the app,
        appCtx = ISuperfluid(msg.sender).appCallbackPush(
            ctx,
            ISuperApp(inputs.account),
            inputs.appAllowanceGranted,
            inputs.appAllowanceUsed,
            inputs.token);
    }

    function _popCallbackStack(
        bytes memory ctx,
        int256 appAllowanceUsedDelta
    )
        private
        returns (bytes memory newCtx)
    {
        // app allowance params stack POP
        return ISuperfluid(msg.sender).appCallbackPop(ctx, appAllowanceUsedDelta);
    }

    /**************************************************************************
     * Misc
     *************************************************************************/

    function max(int256 a, int256 b) internal pure returns (int256) { return a > b ? a : b; }

    function min(int256 a, int256 b) internal pure returns (int256) { return a > b ? b : a; }
}