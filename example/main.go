package main

import (
	"fmt"
	"github.com/aeriuslabs/ezkl-ffi/cgo"
	"os"
)

//import cgo.go from ../cgo/cgo.go

func main() {

	// read artifacts/witness, pk.key, mode.compiles, srs
	witness, err := os.ReadFile("./artifacts/witness.json")
	if err != nil {
		panic(err)
	}

	model, err := os.ReadFile("./artifacts/model.compiled")
	if err != nil {
		panic(err)
	}

	srs, err := os.ReadFile("./artifacts/kzg")
	if err != nil {
		panic(err)
	}

	settings, err := os.ReadFile("./artifacts/settings.json")
	if err != nil {
		panic(err)
	}

	cgo.GenVk(uint64(len(model)), model, uint64(len(srs)), srs, true)
	vk, err := os.ReadFile("./vk.key")
	if err != nil {
		panic(err)
	}

	cgo.GenPk(uint64(len(vk)), vk, uint64(len(model)), model, uint64(len(srs)), srs)
	pk, err := os.ReadFile("./pk.key")
	if err != nil {
		panic(err)
	}

	proof := cgo.Prove(uint64(len(witness)), witness, uint64(len(pk)), pk, uint64(len(model)), model, uint64(len(srs)), srs)
	fmt.Println("proof:", proof)
	proofBytes := []byte(proof)

	verified := cgo.VerifyProof(uint64(len(proof)), proofBytes, uint64(len(vk)), vk, uint64(len(settings)), settings, uint64(len(srs)), srs)
	fmt.Println("verified:", verified)
}
