// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./ERC721A.sol";
import "./AccessControl.sol";
import "./ECDSA.sol";


contract NoobBrave is ERC721A, AccessControl {
    using Strings for uint256;
    uint256 public maxSupply = 2000;
    string public defaultURI;
    string public baseURI;

    uint256 public wlMintLimit = 3;
    uint256 public mintCost = 0.005 ether;

    bool public publicActive;
    bool public wlActive;
    bool public revealed;


    address public withdrawAddress;
    bytes32 public constant TEAM_ROLE = keccak256("TEAM_ROLE");
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    mapping(address => uint256) public amountMintedPerAddr;

    event TEAM_ROLE_ADDED(address _beneficiary);
    event TEAM_ROLE_REMOVED(address _beneficiary);

    constructor(string memory name, string memory symbol, string memory _defaultURI) ERC721A(name, symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(TEAM_ROLE, _msgSender());
        _grantRole(SIGNER_ROLE, address(0xf026a584Ef4D25D196495fC03b6243A375D02eFC));
        defaultURI = _defaultURI;
        wlActive = true;
    }

    function _mintCheck(uint256 _mintAmount) internal view {
        require(_mintAmount > 0, 'Mint amount cannot be zero');
        require(totalSupply() + _mintAmount <= maxSupply, 'Total supply cannot exceed maxSupply');
    }

    function mint(uint256 amount) external payable {
        require(publicActive, "Whitelist mint is NOT active.");
        _mintCheck(amount);
        require(msg.value >= mintCost * amount,'Ether value sent is not sufficient');
        _mint(msg.sender, amount);
    }

    function freeMint(uint256 amount, bytes memory signature) external payable {
        require(wlActive, "White List mint is NOT active.");
        _mintCheck(amount);
        require(_numberMinted(msg.sender) < 1, "You have already used your whitelist quota");
        require(amount <= wlMintLimit, "exceed whitelist limit");
        {
            bytes32 structHash = keccak256(abi.encode(msg.sender));
            bytes32 ethSignedMessageHash = ECDSA.toEthSignedMessageHash(structHash);
            (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
            address signer = ECDSA.recover(ethSignedMessageHash, v, r, s);
            require(hasRole(SIGNER_ROLE, signer), "Invalid signature.");
        }
        _mint(msg.sender, amount);  
    }

    function teamMint(uint256 amount) external onlyRole(TEAM_ROLE) {
        _mintCheck(amount);
        _mint(msg.sender, amount);
    }

    function addTeamRole(address _beneficiary) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(TEAM_ROLE, _beneficiary);

        emit TEAM_ROLE_ADDED(_beneficiary);
    }

    function removeTeamRole(address _beneficiary) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(TEAM_ROLE, _beneficiary);
        
        emit TEAM_ROLE_REMOVED(_beneficiary);
    }

    function addSignerRole(address _beneficiary) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(SIGNER_ROLE, _beneficiary);
    }

    function removeSignerRole(address _beneficiary) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(SIGNER_ROLE, _beneficiary);
    }

    function togglePublicActive() external onlyRole(TEAM_ROLE) {
        publicActive = !publicActive;
    }

    function toggleWlActive() external onlyRole(TEAM_ROLE) {
        wlActive = !wlActive; 
    }

    function setbaseURI(string memory _baseURI) external onlyRole(TEAM_ROLE) {
        baseURI = _baseURI;
    }

    function setWithdrawAddress(address _addr) external onlyRole(DEFAULT_ADMIN_ROLE) {
        withdrawAddress = _addr;
    }

    function withdrawAll() external payable onlyRole(DEFAULT_ADMIN_ROLE) {
        require(payable(withdrawAddress).send(address(this).balance));
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory)
    {
        if (!_exists(tokenId)) _revert(URIQueryForNonexistentToken.selector);

        if (!revealed) {
            return defaultURI;
        }

        return string(abi.encodePacked(baseURI, tokenId.toString()));
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721A, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}