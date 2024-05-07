// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

// ====================================================================
//             _        ______     ___   _______          _
//            / \     .' ___  |  .'   `.|_   __ \        / \
//           / _ \   / .'   \_| /  .-.  \ | |__) |      / _ \
//          / ___ \  | |   ____ | |   | | |  __ /      / ___ \
//        _/ /   \ \_\ `.___]  |\  `-'  /_| |  \ \_  _/ /   \ \_
//       |____| |____|`._____.'  `.___.'|____| |___||____| |____|
// ====================================================================
// ======================= OwnableAccessControl =======================
// ====================================================================

import { AgoraOwnable2Step, ConstructorParams as AgoraOwnable2StepParams } from "./AgoraOwnable2Step.sol";

struct ConstructorParams {
    address ownerAddress;
}

/// @notice OwnableAccessControl is a contract that provides a generic access control mechanism.
/// It is designed to be inherited by other contracts that require access control.
/// The contract owner can grant and revoke roles to other accounts.
abstract contract OwnableAccessControl is AgoraOwnable2Step {
    mapping(address _account => bool _isRole) public isRole;

    constructor(
        ConstructorParams memory _params
    ) AgoraOwnable2Step(AgoraOwnable2StepParams({ ownerAddress: _params.ownerAddress })) {}

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _requireIsRole(address account) internal view virtual {
        if (!isRole[account]) revert AccessControlUnauthorizedAccount({ account: account });
    }

    //==============================================================================
    // Functions: External Stateful Functions
    //==============================================================================

    function grantRole(address account) public virtual returns (bool _isRoleGranted) {
        _requireSenderIsOwner();
        _isRoleGranted = _grantRole({ account: account });
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(address account) public virtual returns (bool _isRoleRevoked) {
        _requireSenderIsOwner();
        _isRoleRevoked = _revokeRole({ account: account });
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole() public virtual returns (bool _isRoleRenounced) {
        _requireIsRole(msg.sender);
        _isRoleRenounced = _revokeRole(msg.sender);
    }

    //==============================================================================
    // Internal Stateful Functions
    //==============================================================================

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(address account) internal virtual returns (bool) {
        if (!isRole[account]) {
            isRole[account] = true;
            emit RoleGranted(account);
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` to `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(address account) internal virtual returns (bool) {
        if (isRole[account]) {
            isRole[account] = false;
            emit RoleRevoked(account);
            return true;
        } else {
            return false;
        }
    }

    //==============================================================================
    // Events
    //==============================================================================

    event RoleRevoked(address indexed account);

    event RoleGranted(address indexed account);

    //==============================================================================
    // Errors
    //==============================================================================

    error AccessControlUnauthorizedAccount(address account);
}
