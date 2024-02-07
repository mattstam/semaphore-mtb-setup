package keys

import (
	"bufio"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/worldcoin/semaphore-mtb-setup/phase2"
)

func extractKeys(phase2Path string) error {
	phase2File, err := os.Open(phase2Path)
	if err != nil {
		return err
	}
	defer phase2File.Close()

	// Evaluations
	evalsFile, err := os.Open("evals")
	if err != nil {
		return err
	}
	defer evalsFile.Close()

	// Use buffered IO to write parameters efficiently
	ph2Reader := bufio.NewReader(phase2File)
	evalsReader := bufio.NewReader(evalsFile)

	var header phase2.Header
	if err := header.Read(ph2Reader); err != nil {
		return err
	}
	decEvals := bn254.NewDecoder(evalsReader)

	var ckk []bn254.G1Affine
	if err := decEvals.Decode(&ckk); err != nil {
		return err
	}

	// Setup Pedersen commitment
	pks, vk, err := pedersen.Setup(ckk)
	if err != nil {
		return err
	}

	vkFile, err := os.Create("vk")
	if err != nil {
		return err
	}
	defer vkFile.Close()

	// Write VK
	if _, err := vk.WriteTo(vkFile); err != nil {
		return err
	}

	// Write PKs
	for i, pk := range pks {
		pkFile, err := os.Create("pk" + fmt.Sprintf("%d", i))
		if err != nil {
			return err
		}
		defer pkFile.Close()
		if _, err := pk.WriteTo(pkFile); err != nil {
			return err
		}
	}

	return nil
}

func ExtractKeys(phase2Path string) error {
	fmt.Printf("Extracting keys from %s\n", phase2Path)
	return extractKeys(phase2Path)
}

func ExportSol(session string) error {
	filename := session + ".sol"
	fmt.Printf("Exporting %s\n", filename)
	f, _ := os.Open(session + ".vk.save")
	verifyingKey := groth16.NewVerifyingKey(ecc.BN254)
	_, err := verifyingKey.ReadFrom(f)
	if err != nil {
		panic(fmt.Errorf("read file error"))
	}
	err = f.Close()
	f, err = os.Create(filename)
	if err != nil {
		panic(err)
	}
	err = verifyingKey.ExportSolidity(f)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s has been extracted successfully\n", filename)
	return nil
}

func filterInfinityG1(buff []bn254.G1Affine) ([]bn254.G1Affine, []bool, uint64) {
	infinityAt := make([]bool, len(buff))
	filtered := make([]bn254.G1Affine, len(buff))
	j := 0
	for i, e := range buff {
		if e.IsInfinity() {
			infinityAt[i] = true
			continue
		}
		filtered[j] = buff[i]
		j++
	}
	return filtered[:j], infinityAt, uint64(len(buff) - j)
}

func filterInfinityG2(buff []bn254.G2Affine) ([]bn254.G2Affine, []bool, uint64) {
	infinityAt := make([]bool, len(buff))
	filtered := make([]bn254.G2Affine, len(buff))
	j := 0
	for i, e := range buff {
		if e.IsInfinity() {
			infinityAt[i] = true
			continue
		}
		filtered[j] = buff[i]
		j++
	}
	return filtered[:j], infinityAt, uint64(len(buff) - j)

}
