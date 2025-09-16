package utils

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// Mimc 对字符串数据进行 MiMC 哈希处理，返回哈希结果（字节数组）
func Mimc(data string) *fr.Element {
	input := []byte(data)
	// 创建 MiMC 哈希器
	hFunc := mimc.NewMiMC()
	input = leafSum(hFunc, input)
	return new(fr.Element).SetBytes(input)
	// var inputInt *big.Int

	// // 判断传入的是字符还是数字
	// if tools.IsAlphabetic(data) {
	// 	inputInt = new(big.Int).SetBytes([]byte(data))
	// } else {
	// 	inputInt = new(big.Int)
	// 	var ok bool
	// 	inputInt, ok = inputInt.SetString(data, 10)
	// 	if !ok {
	// 		panic("invalid numeric string input")
	// 	}
	// }

	// // 转换为有限域元素
	// var inputElem fr.Element
	// inputElem.SetBigInt(inputInt)

	// // 创建 MiMC 哈希器
	// hFunc := mimc.NewMiMC()
	// hFunc.Write(inputElem.Marshal())

	// // 获取哈希结果
	// XhashBytes := hFunc.Sum(nil)
	// // 将字节数组转换为有限域元素
	// Xhash := new(fr.Element).SetBytes(XhashBytes)
	// return Xhash
}
