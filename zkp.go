package zkdid

func GenerateZKMerkleRoot(dataList [][]byte, seed []byte) []byte {
	sequence := GenerateSequence256(seed, len(dataList))
	newDataList := make([][]byte, len(dataList))
	for i, data := range dataList {
		newDataList[i] = append(sequence[i], data...)
	}
	return CalcMerkleRoot(newDataList)
}
func GenerateZKMerkleEvidence(dataList [][]byte, seed []byte, idx uint) (*ZKEvidence, error) {
	sequence := GenerateSequence256(seed, len(dataList))
	newDataList := make([][]byte, len(dataList))
	for i, data := range dataList {
		newDataList[i] = append(sequence[i], data...)
	}
	evidence, err := CalcMerkleEvidence(newDataList, idx)
	if err != nil {
		return nil, err
	}
	return &ZKEvidence{
		Salt:          sequence[idx],
		RawData:       evidence.RawData[len(sequence[idx]):],
		MerkleSibling: evidence.MerkleSibling,
		Index:         evidence.Index,
		MerkleRoot:    evidence.MerkleRoot,
	}, nil
}

func ZKProve(evidence *ZKEvidence) bool {
	ev := &Evidence{
		RawData:       append(evidence.Salt, evidence.RawData...),
		MerkleSibling: evidence.MerkleSibling,
		Index:         evidence.Index,
		MerkleRoot:    evidence.MerkleRoot,
	}
	return Prove(ev)
}
