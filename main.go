package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	skyline_program "solsdk/generated"
	"time"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

func StartTestNode() (*exec.Cmd, error) {
	cmd := exec.Command("solana-test-validator", "-r", "-q")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start test node: %w", err)
	}

	return cmd, nil
}

func WaitForNode(cli *rpc.Client) error {
	for {
		finalizedSlot, err := cli.GetSlot(
			context.TODO(),
			rpc.CommitmentFinalized,
		)
		if err != nil || finalizedSlot == 0 {
			time.Sleep(time.Second)
			fmt.Println("I dalje 0")
			continue
		}

		if finalizedSlot > 0 {
			fmt.Println(finalizedSlot)
			break
		}
	}

	return nil
}

func Airdrop(keypairPath string) error {
	cmd := exec.Command("solana",
		"airdrop",
		"-u", "localhost",
		"-k", keypairPath,
		"--commitment", "finalized",
		"10")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to airdrop: %w", err)
	}

	return cmd.Wait()
}

func Deploy(feePayer string, programKey string, buildPath string) error {
	cmd := exec.Command("solana",
		"program", "deploy",
		"-u", "localhost",
		"--fee-payer", feePayer,
		"-k", programKey,
		"--commitment", "finalized",
		buildPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to deploy: %w", err)
	}

	return cmd.Wait()
}

func main() {
	cmd, err := StartTestNode()
	if err != nil {
		fmt.Println(err)
		return
	}

	defer cmd.Process.Kill()

	cli := rpc.New("http://127.0.0.1:8899")

	if err := WaitForNode(cli); err != nil {
		fmt.Println(err)
		return
	}

	if err := Airdrop("./test.json"); err != nil {
		fmt.Println(err)
		return
	}

	pk, err := solana.PrivateKeyFromSolanaKeygenFile("./test.json")
	if err != nil {
		fmt.Println(err)
		return
	}

	res, err := cli.GetBalance(context.TODO(), pk.PublicKey(), rpc.CommitmentConfirmed)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(res.Value)

	if err := Deploy("./test.json", "./skyline_program-keypair.json", "./skyline_program.so"); err != nil {
		fmt.Println("OVDE", err)
		return
	}

	time.Sleep(time.Second * 20)

	programPk, err := solana.PrivateKeyFromSolanaKeygenFile("./skyline_program-keypair.json")
	if err != nil {
		fmt.Println("OVDE 2:", err)
		return
	}

	res1, err := cli.GetAccountInfo(context.TODO(), programPk.PublicKey())
	if err != nil {
		fmt.Println("OVDE 3:", err)
		return
	}

	fmt.Println(res1.Value.Executable)

	fmt.Println("Executable:", res1.Value.Executable)
	fmt.Println("Owner:     ", res1.Value.Owner)
	fmt.Println(res1.Value)

	vals := make([]*solana.Wallet, 4)
	for i := range 4 {
		vals[i] = solana.NewWallet()
	}

	valsPKs := make([]solana.PublicKey, 4)
	for i := range 4 {
		valsPKs[i] = vals[i].PublicKey()
	}

	pdaVS, _, err := solana.FindProgramAddress([][]byte{skyline_program.VALIDATOR_SET_SEED}, skyline_program.ProgramID)
	if err != nil {
		fmt.Println(err)
		return
	}

	pdaVault, _, err := solana.FindProgramAddress([][]byte{skyline_program.VAULT_SEED}, skyline_program.ProgramID)
	if err != nil {
		fmt.Println(err)
		return
	}

	a, err := skyline_program.NewInitializeInstruction(
		valsPKs,
		new(uint64),
		pk.PublicKey(),
		pdaVS,
		pdaVault,
		solana.SystemProgramID,
	)

	fmt.Println("SDK ProgramID:      ", skyline_program.ProgramID)
	fmt.Println("Deployed ProgramID: ", programPk.PublicKey())

	if err != nil {
		fmt.Println("OVDE1", err)
		return
	}

	latest, err := cli.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		fmt.Println("OVDE2", err)
		return
	}

	b := solana.NewTransactionBuilder().AddInstruction(a)
	b.SetRecentBlockHash(latest.Value.Blockhash)
	b.SetFeePayer(pk.PublicKey())
	tx, err := b.Build()
	if err != nil {
		fmt.Print("OVDE3", err)
		return
	}

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		return &pk
	})

	if err != nil {
		fmt.Println("OVDE4", err)
		return
	}

	_, err = cli.SendTransactionWithOpts(context.TODO(), tx, rpc.TransactionOpts{
		PreflightCommitment: rpc.CommitmentFinalized,
	})
	if err != nil {
		fmt.Println("OVDE JE GRESKA MJAU:", err)
		return
	}

	time.Sleep(time.Second * 20)

	resp, err := cli.GetAccountInfo(context.TODO(), pdaVS)
	if err != nil {
		fmt.Println("OVDR5", err)
		return
	}

	rdd := &skyline_program.ValidatorSet{}

	borshDec := bin.NewBorshDecoder(resp.GetBinary())
	err = borshDec.Decode(&rdd)
	if err != nil {
		panic(err)
	}

	fmt.Println("Na kontraktu:")
	for i, v := range rdd.Signers {
		fmt.Println(i, ":", v)
	}

	fmt.Println("Nasi:")
	for i, v := range valsPKs {
		fmt.Println(i, ":", v)
	}

	//fmt.Println(rd)
}
