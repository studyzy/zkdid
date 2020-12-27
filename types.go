package zkdid

type Evidence struct {
	RawData       []byte
	MerkleSibling [][]byte
	Index         uint
	MerkleRoot    []byte
}
type ZKEvidence struct {
	Salt          []byte
	RawData       []byte
	MerkleSibling [][]byte
	Index         uint
	MerkleRoot    []byte
}
