use ethers::contract::abigen;

abigen!(
    Semaphore,
    r#"[
        event LeafInsertion(uint256 indexed leaf, uint256 indexed leafIndex)
        function insertIdentity(uint256 _identityCommitment) public onlyOwner returns (uint256)
    ]"#,
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(
    WalletClaims,
    r#"[
        function commit(uint256[8] calldata proof, bytes calldata pubKeyHash, uint256 batchId, uint256 commitmentIdx, uint256 transferIdx, uint256 _root, uint256 _nullifierHash) external
    ]"#,
);
