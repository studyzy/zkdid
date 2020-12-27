package zkdid

import "encoding/binary"

func GenerateSequence256(seed []byte, count int) [][]byte {
	result := [][]byte{}
	current := seed
	for i := 0; i < count; i++ {
		current = getHash(current)
		result = append(result, current)
	}
	return result
}
func GenerateSequence128(seed []byte, count int) [][]byte {
	result := [][]byte{}
	current := seed
	for i := 0; i < count; i++ {
		current = getHash(current)
		result = append(result, current[0:16])
	}
	return result
}
func GenerateSequenceUInt64(seed []byte, count int) []uint64 {
	result := []uint64{}
	current := seed
	for i := 0; i < count; i++ {
		current = getHash(current)
		x := binary.BigEndian.Uint64(current[0:8])
		result = append(result, x)
	}
	return result
}
