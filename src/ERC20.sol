// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract ERC20 {
    string private _name;
    string private _symbol;
    bool public _pause;
    address private _owner;
    uint256 private _totalSupply;
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    string private version;

    mapping(address => mapping(address => uint256)) public allowance; // _allowance[owner][spender]
    mapping(address => uint256) private _balances;
    mapping(address => uint256) public nonces;

    modifier checkpaused() {
        require(!_pause, "not allowed while paused");
        _;
    }

    event Transfer(address from, address to, uint256 value);
    event Approval(address from, address to, uint256 value);

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
        _owner = msg.sender;
        _totalSupply = 100 * 10 ** decimals();
        _balances[_owner] = _totalSupply;
        version = "1";
    }

    function transfer(address _to, uint256 _value) public checkpaused returns (bool success) {
        _transfer(msg.sender, _to, _value);
        emit Transfer(msg.sender, _to, _value);
        success = true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        spendallowance(_from, _to, _value);
        _transfer(_from, _to, _value);
        emit Transfer(_from, _to, _value);
        success = true;
    }

    function _transfer(address _from, address _to, uint256 _value) public {
        require(_balances[_from] >= _value, "you don't have enough token");

        _balances[_from] -= _value;
        _balances[_to] += _value;
    }

    function pause() public {
        require(msg.sender==_owner, "no permission");
        _pause = true;
    }

    function unpause() public {
        require(msg.sender==_owner, "no permission");
        _pause = false;
    }

    function approve(address spender, uint256 value) public {
        address owner = msg.sender;
        require(owner != address(0) && spender != address(0), "address 0 not allowed");

        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function spendallowance(address owner, address spender, uint256 _value) public {
        require(allowance[owner][spender] >= _value, "no enough allowance");

        allowance[owner][spender] -= _value;
    }

    function decimals() public view returns (uint8) {
        return 18;
    }

    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/EIP712.sol
    function _buildDomainSeparator() private view returns (bytes32) {
        bytes32 _hashedName = keccak256(bytes(_name));
        bytes32 _hashedVersion = keccak256(bytes(version));
        bytes32 TYPE_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

        return keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this)));
    } 

    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MessageHashUtils.sol
    function _toTypedDataHash(bytes32 structHash) public view returns (bytes32 digest) {
        digest = keccak256(abi.encodePacked(hex"19_01", _buildDomainSeparator(), structHash));
    }

    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/ERC20Permit.sol
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        require(block.timestamp < deadline, "permit deadline has expired");

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner], deadline));
        bytes32 hash = _toTypedDataHash(structHash);
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "INVALID_SIGNER");

        allowance[owner][spender] = value;

        // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Nonces.sol
        nonces[owner]++; // _useNonce
    }
}