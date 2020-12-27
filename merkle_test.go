package zkdid

import (
	"encoding/hex"
	"testing"
)

func TestBuildMerkleTreeStore(t *testing.T) {
	txs := [][]byte{
		[]byte("tx1"),
		[]byte("tx2"),
		[]byte("tx3"),
		[]byte("tx4"),
	}
	result := BuildMerkleTreeStore(txs)
	for i, n := range result {
		t.Logf("%d,%x\n", i, n)
	}
}
func TestPickTx2Proof(t *testing.T) {
	tx1Hash, _ := hex.DecodeString("709b55bd3da0f5a838125bd0ee20c5bfdd7caba173912d4281cae816b79a201b")
	hash34, _ := hex.DecodeString("5709445d1034999688c7261a7c9cd07b521fcd02b97c71fb30ca85b9104487ca")
	root, _ := hex.DecodeString("ea59a369466be42d1a4783f09ae0721a5a157d6dba9c4b053d407b5a4b9af145")
	path := [][]byte{}
	path = append(path, tx1Hash)
	path = append(path, hash34)
	pass := Prove(&Evidence{
		RawData:       []byte("tx2"),
		MerkleSibling: path,
		Index:         1,
		MerkleRoot:    root,
	})
	t.Log(pass)
}
func TestBuildMerkleTreeFor5Txs(t *testing.T) {
	txs := [][]byte{
		[]byte("tx1"),
		[]byte("tx2"),
		[]byte("tx3"),
		[]byte("tx4"),
		[]byte("tx5"),
	}
	result := BuildMerkleTreeStore(txs)
	for i, n := range result {
		t.Logf("%d,%d\n", i, n)
	}
	nodes, _ := CalcMerkleEvidence(txs, 4)
	for _, node := range nodes.MerkleSibling {
		t.Logf("%d", node)
	}
	nodes.RawData = []byte("tx5")
	pass := Prove(nodes)
	if pass {
		t.Log(pass)
	} else {
		t.Fail()
	}
}
