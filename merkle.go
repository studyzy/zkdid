package zkdid

import (
	"bytes"
	"crypto/sha256"
	"math"
)

// nextPowerOfTwo returns the next highest power of two from a given number if
// it is not already a power of two.  This is a helper function used during the
// calculation of a merkle tree.
func nextPowerOfTwo(n int) int {
	// Return the number if it's already a power of 2.
	if n&(n-1) == 0 {
		return n
	}

	// Figure out and return the next power of two.
	exponent := uint(math.Log2(float64(n))) + 1
	return 1 << exponent // 2^exponent
}
func getHash(input []byte) []byte {
	h := sha256.New()
	h.Write(input)
	return h.Sum(nil)
}

// hashMerkleBranches takes two hashes, treated as the left and right tree
// nodes, and returns the hash of their concatenation.  This is a helper
// function used to aid in the generation of a merkle tree.
func hashMerkleBranches(left []byte, right []byte) []byte {
	// Concatenate the left and right nodes.
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// BuildMerkleTreeStore creates a merkle tree from a slice of transactions,
// stores it using a linear array, and returns a slice of the backing array.  A
// linear array was chosen as opposed to an actual tree structure since it uses
// about half as much memory.  The following describes a merkle tree and how it
// is stored in a linear array.
//
// A merkle tree is a tree in which every non-leaf node is the hash of its
// children nodes.  A diagram depicting how this works for bitcoin transactions
// where h(x) is a double sha256 follows:
//
//	         root = h1234 = h(h12 + h34)
//	        /                           \
//	  h12 = h(h1 + h2)            h34 = h(h3 + h4)
//	   /            \              /            \
//	h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
//
// The above stored as a linear array is as follows:
//
// 	[h1 h2 h3 h4 h12 h34 root]
//
// As the above shows, the merkle root is always the last element in the array.
//
// The number of inputs is not always a power of two which results in a
// balanced tree structure as above.  In that case, parent nodes with no
// children are also zero and parent nodes with only a single left node
// are calculated by concatenating the left node with itself before hashing.
// Since this function uses nodes that are pointers to the hashes, empty nodes
// will be nil.
//
// The additional bool parameter indicates if we are generating the merkle tree
// using witness transaction id's rather than regular transaction id's. This
// also presents an additional case wherein the wtxid of the coinbase transaction
// is the zeroHash.
func BuildMerkleTreeStore(transactions [][]byte) [][]byte {
	// Calculate how many entries are required to hold the binary merkle
	// tree as a linear array and create an array of that size.
	nextPoT := nextPowerOfTwo(len(transactions))
	arraySize := nextPoT*2 - 1
	merkles := make([][]byte, arraySize)

	// Create the base transaction hashes and populate the array with them.
	for i, tx := range transactions {
		// If we're computing a witness merkle root, instead of the
		// regular txid, we use the modified wtxid which includes a
		// transaction's witness data within the digest. Additionally,
		// the coinbase's wtxid is all zeroes.
		merkles[i] = getHash(tx)
	}

	// Start the array offset after the last transaction and adjusted to the
	// next power of two.
	offset := nextPoT
	for i := 0; i < arraySize-1; i += 2 {
		switch {
		// When there is no left child node, the parent is nil too.
		case merkles[i] == nil:
			merkles[offset] = nil

		// When there is no right child, the parent is generated by
		// hashing the concatenation of the left child with itself.
		case merkles[i+1] == nil:
			newHash := hashMerkleBranches(merkles[i], merkles[i])
			merkles[offset] = newHash

		// The normal case sets the parent node to the double sha256
		// of the concatentation of the left and right children.
		default:
			newHash := hashMerkleBranches(merkles[i], merkles[i+1])
			merkles[offset] = newHash
		}
		offset++
	}

	return merkles
}

//传入数据列表，计算默克尔根
func CalcMerkleRoot(dataList [][]byte) []byte {
	hashes := BuildMerkleTreeStore(dataList)
	return hashes[len(hashes)-1]
}

// 传入默克尔证明的对象，返回证明是否正确
func Prove(evidence *Evidence) bool {
	txid := getHash(evidence.RawData)
	merkleRoot := evidence.MerkleRoot
	intermediateNodes := evidence.MerkleSibling
	index := evidence.Index
	// Shortcut the empty-block case
	if bytes.Equal(txid[:], merkleRoot[:]) && index == 0 && len(intermediateNodes) == 0 {
		return true
	}

	current := txid
	idx := index
	proofLength := len(intermediateNodes)

	numSteps := (proofLength)

	for i := 0; i < numSteps; i++ {
		next := intermediateNodes[i]
		if idx%2 == 1 {
			current = hashMerkleBranches(next, current)
		} else {
			current = hashMerkleBranches(current, next)
		}
		idx >>= 1
	}

	return bytes.Equal(current, merkleRoot)
}

//传入数据列表和某个需要验证的数据的Index，返回默克尔验证所需的对象
func CalcMerkleEvidence(dataList [][]byte, idx uint) (*Evidence, error) {
	evidence := &Evidence{Index: idx, RawData: dataList[idx]}
	merkleList := BuildMerkleTreeStore(dataList)
	path := [][]byte{}
	dep := int(math.Log2(float64(len(merkleList) + 1)))

	evidence.MerkleRoot = merkleList[len(merkleList)-1]
	merkleList = merkleList[:len(merkleList)-1]
	for i := 1; i < dep; i++ {
		levelCount := int(math.Pow(2, float64(i)))           //该层有多少个元素
		levelList := merkleList[len(merkleList)-levelCount:] //该层的元素列表
		merkleList = merkleList[:len(merkleList)-levelCount]
		mask := idx >> (dep - i - 1)
		if mask%2 == 0 { //left
			mask++ //取右边那个
		} else {
			mask-- //取左边那个
		}
		if levelList[mask] == nil { //单数的情况，重复取左边元素
			mask--
		}
		path = leftJoin(levelList[mask], path)
	}
	evidence.MerkleSibling = path
	return evidence, nil
}
func leftJoin(n []byte, list [][]byte) [][]byte {
	result := make([][]byte, len(list)+1)
	result[0] = n
	for i, x := range list {
		result[i+1] = x
	}
	return result
}