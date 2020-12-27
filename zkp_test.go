package zkdid

import (
	"bytes"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

//用户A（出生于1985年）使用零知识证明自己已经年满18岁，但是不暴露具体生日
func TestZKProve(t *testing.T) {
	birthYear := 1985
	checkAge := 18
	rand.Seed(time.Now().UnixNano())
	seed := strconv.Itoa(rand.Int())
	t.Logf("随机种子为：%s", seed)
	//构造从1900到2020的数据列表，列表数据内容为：{年}+"Y"或者 {年}+"N",其中Y表示当年已经出生，N表示当年还没有出生
	dataList := [][]byte{}
	var data string
	for i := 1900; i <= 2020; i++ {
		if i >= birthYear {
			data = fmt.Sprintf("%dY", i)
		} else {
			data = fmt.Sprintf("%dN", i)
		}
		dataList = append(dataList, []byte(data))
	}
	//增加下边界数据
	if birthYear < 1900 {
		dataList = append(dataList, []byte("<1900Y"))
	} else {
		dataList = append(dataList, []byte("<1900N"))
	}
	//增加上边界数据
	if birthYear > 2020 {
		dataList = append(dataList, []byte(">2020Y"))
	} else {
		dataList = append(dataList, []byte(">2020N"))
	}
	root := GenerateZKMerkleRoot(dataList, []byte(seed))
	//公安部门对该root进行签名，所以能够通过默克尔验证，则可信。
	//接下来用户证明自己大于18岁
	//年满18岁，就是18年前已经出生
	y := time.Now().AddDate(-checkAge, 0, 0)
	t.Logf("%d年前为:%d\n", checkAge, y.Year())
	evidence, _ := GenerateZKMerkleEvidence(dataList, []byte(seed), uint(y.Year()-1900))
	t.Logf("提交的数据：%s,完整证据：%#v", evidence.RawData, evidence)
	//验证方收到evidence，进行验证
	if !bytes.Equal(evidence.MerkleRoot, root) {
		t.Errorf("Root[%x]不是公安部门签名过的Root[%x]", evidence.MerkleRoot, root)
	}
	pass := ZKProve(evidence)
	if pass {
		t.Log("证据验证通过！")
	} else {
		t.Error("证据验证失败")
	}
	if evidence.RawData[len(evidence.RawData)-1] == byte('Y') {
		t.Logf("%s 年龄验证通过", evidence.RawData)
	} else {
		t.Logf("%s 年龄验证失败", evidence.RawData)
	}
}

//用户A有姓名、生日、住址、民族、照片等信息，现在只选择暴露姓名，其他都不暴露
func TestSelectProve(t *testing.T) {
	dataList := [][]byte{
		[]byte("姓名：深蓝"),
		[]byte("生日：19840804"),
		[]byte("住址：A省B市C区D街道123号"),
		[]byte("民族：汉"),
		[]byte("照片：Qm234243twedfsasd..."), //照片内容编码
	}
	rand.Seed(time.Now().UnixNano())
	seed := strconv.Itoa(rand.Int())
	t.Logf("随机种子为：%s", seed)
	root := GenerateZKMerkleRoot(dataList, []byte(seed))
	//公安部门对该root进行签名，所以能够通过默克尔验证，则可信。
	//接下来用户披露自己的姓名，并给出证明
	evidence, _ := GenerateZKMerkleEvidence(dataList, []byte(seed), 0)
	t.Logf("用户给出的断言：%s，证明为：%#v", evidence.RawData, evidence)

	//验证方收到evidence，进行验证
	//验证方会先对root的签名进行验证，保证root是公安机关签名的，这里签名验证就忽略，跳过
	if !bytes.Equal(evidence.MerkleRoot, root) {
		t.Errorf("Root[%x]不是公安部门签名过的Root[%x]", evidence.MerkleRoot, root)
	}
	pass := ZKProve(evidence)
	if pass {
		t.Logf("证据验证通过！断言「%s」成立", evidence.RawData)
	} else {
		t.Error("证据验证失败")
	}
}
