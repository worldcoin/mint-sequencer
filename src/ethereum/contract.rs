use ethers::contract::abigen;

abigen!(
    Semaphore,
    r#"[
        event LeafInsertion(uint256 indexed leaf, uint256 indexed leafIndex)
        function insertIdentity(uint256 _identityCommitment) public onlyOwner returns (uint256)
        function root() public view returns (uint256)
        function preBroadcastCheck(bytes memory _signal, uint256[8] memory _proof, uint256 _root, uint256 _nullifiersHash, uint256 _signalHash, uint232 _externalNullifier) public view returns (bool)
    ]"#,
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(
    WalletClaims,
    r#"[
        function commit(uint256[8] calldata proof, bytes calldata pubKeyHash, uint256 batchId, uint256 commitmentIdx, uint256 transferIdx, uint256 _root, uint256 _nullifierHash) external
    ]"#,
);
