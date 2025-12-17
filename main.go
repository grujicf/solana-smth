package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	skyline_program "solsdk/generated"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/ws"

	associatedtokenaccount "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
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

func CreateTokenAccount(cli *rpc.Client, wsCli *ws.Client, pk solana.PrivateKey) (*solana.PublicKey, error) {
	tokenPk, err := solana.NewRandomPrivateKey()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	block, err := cli.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	rent, err := cli.GetMinimumBalanceForRentExemption(context.Background(), token.MINT_SIZE, rpc.CommitmentFinalized)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	caIx := system.NewCreateAccountInstruction(rent+1, uint64(token.MINT_SIZE), token.ProgramID, pk.PublicKey(), tokenPk.PublicKey()).Build()

	mintIx := token.NewInitializeMint2Instruction(9, pk.PublicKey(), pk.PublicKey(), tokenPk.PublicKey())
	mintTx, err := solana.NewTransactionBuilder().AddInstruction(caIx).AddInstruction(mintIx.Build()).SetFeePayer(pk.PublicKey()).SetRecentBlockHash(block.Value.Blockhash).Build()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	_, err = mintTx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(pk.PublicKey()) {
			return &pk
		}
		if key.Equals(tokenPk.PublicKey()) {
			return &tokenPk
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	sigMint, err := cli.SendTransaction(context.TODO(), mintTx)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	subMint, err := wsCli.SignatureSubscribe(sigMint, rpc.CommitmentFinalized)
	if err != nil {
		fmt.Println("Subscription error:", err)
		return nil, err
	}

	rd := <-subMint.Response()
	if rd.Value.Err != nil {
		fmt.Println("Transaction failed:", rd.Value.Err)
		return nil, err
	}

	ret := tokenPk.PublicKey()
	return &ret, nil
}

func MintToAccount(cli *rpc.Client, wsCli *ws.Client, pk solana.PrivateKey, receiver solana.PublicKey, mint solana.PublicKey) (ata solana.PublicKey, err error) {
	ata, _, err = solana.FindAssociatedTokenAddress(receiver, mint)
	if err != nil {
		return
	}

	var instructions []solana.Instruction

	ataInfo, err := cli.GetAccountInfo(context.Background(), ata)
	if err != nil || ataInfo.Value == nil {
		ataIx := associatedtokenaccount.NewCreateInstruction(
			pk.PublicKey(),
			receiver,
			mint,
		).Build()
		instructions = append(instructions, ataIx)
	}

	mintToIx := token.NewMintToInstruction(1_000_000_000, mint, ata, pk.PublicKey(), []solana.PublicKey{}).Build()
	instructions = append(instructions, mintToIx)

	blockhash, err := cli.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		return
	}

	builder := solana.NewTransactionBuilder().SetRecentBlockHash(blockhash.Value.Blockhash).SetFeePayer(pk.PublicKey())
	for _, ix := range instructions {
		builder.AddInstruction(ix)
	}

	tx, err := builder.Build()
	if err != nil {
		return
	}

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(pk.PublicKey()) {
			return &pk
		}
		return nil
	})
	if err != nil {
		return
	}

	sig, err := cli.SendTransaction(context.TODO(), tx)
	if err != nil {
		return
	}

	sub, err := wsCli.SignatureSubscribe(sig, rpc.CommitmentFinalized)
	if err != nil {
		return
	}

	result := <-sub.Response()
	if result.Value.Err != nil {
		err = fmt.Errorf("mint to account transaction failed: %v", result.Value.Err)
		return
	}

	return
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	wsCli, err := ws.Connect(ctx, "ws://127.0.0.1:8900")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer wsCli.Close()

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

	sub1, err := wsCli.LogsSubscribeMentions(skyline_program.ProgramID, rpc.CommitmentFinalized)
	if err != nil {
		fmt.Println("MJAU3", err)
		return
	}
	defer sub1.Unsubscribe()

	go func() {
		for {
			select {
			case res := <-sub1.Response():
				for _, log := range res.Value.Logs {
					if !strings.Contains(log, "Program data: ") {
						continue
					}

					decoded, err := base64.RawStdEncoding.DecodeString(log[14:])
					if err != nil {
						fmt.Println("Failed to decode log:", err)
						continue
					}

					ret, err := skyline_program.ParseAnyEvent(decoded)
					if err != nil {
						fmt.Println("Failed to parse event:", err)
						continue
					}

					fmt.Printf("Parsed event: %+v\n", ret)
					switch e := ret.(type) {
					case *skyline_program.TransactionExecutedEvent:
						fmt.Println("TransactionExecutedEvent:", e.TransactionId, e.BatchId)
					case *skyline_program.ValidatorSetUpdatedEvent:
						fmt.Println("ValidatorSetUpdatedEvent:", e)
					default:
						fmt.Println("Unknown event type")
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

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

	sig, err := cli.SendTransaction(context.TODO(), tx)
	if err != nil {
		fmt.Println("OVDE JE GRESKA MJAU:", err)
		return
	}
	sub, err := wsCli.SignatureSubscribe(sig, rpc.CommitmentFinalized)
	if err != nil {
		fmt.Println("Subscription error:", err)
		return
	}

	result := <-sub.Response()
	if result.Value.Err != nil {
		fmt.Println("Transaction failed:", result.Value.Err)
		return
	}

	resp, err := cli.GetAccountInfo(context.TODO(), pdaVS)
	if err != nil {
		fmt.Println("OVDR5", err)
		return
	}

	rdd := &skyline_program.ValidatorSet{}
	if rdd.Unmarshal(resp.GetBinary()[8:]) != nil {
		panic("PANICIM")
	}
	fmt.Println("Na kontraktu:")
	for i, v := range rdd.Signers {
		fmt.Println(i, ":", v)
	}

	fmt.Println("Nasi:")
	for i, v := range valsPKs {
		fmt.Println(i, ":", v)
	}

	mint, err := CreateTokenAccount(cli, wsCli, pk)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Created token account:", mint)

	ata, err := MintToAccount(cli, wsCli, pk, pdaVault, *mint)
	if err != nil {
		fmt.Println(err)
		return
	}

	balance, err := cli.GetTokenAccountBalance(ctx, ata, rpc.CommitmentFinalized)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Vault ATA:", ata)
	fmt.Println("Vault balance:", balance.Value.Amount)

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, 2)
	fmt.Println("BUF", buf)

	pdaBridgingTx, _, err := solana.FindProgramAddress([][]byte{skyline_program.BRIDGING_TRANSACTION_SEED, buf}, skyline_program.ProgramID)
	if err != nil {
		fmt.Println(err)
		return
	}

	pera := solana.NewWallet()
	perinAta, _, err := solana.FindAssociatedTokenAddress(pera.PublicKey(), *mint)
	if err != nil {
		fmt.Println(err)
		return
	}

	ins, err := skyline_program.NewBridgeTransactionInstruction(1_000,
		2,
		pk.PublicKey(),
		pdaVS,
		pdaBridgingTx,
		*mint,
		pera.PublicKey(),
		perinAta,
		pdaVault,
		ata,
		solana.TokenProgramID,
		solana.SystemProgramID,
		solana.SPLAssociatedTokenAccountProgramID,
	)

	var accounts []*solana.AccountMeta
	accounts = append(accounts, ins.Accounts()...)
	for _, v := range vals {
		accounts = append(accounts, &solana.AccountMeta{
			PublicKey:  v.PublicKey(),
			IsSigner:   true,
			IsWritable: false,
		})
	}

	data, err := ins.Data()
	if err != nil {
		fmt.Println(err)
		return
	}

	ix := solana.NewInstruction(skyline_program.ProgramID, accounts, data)
	if err != nil {
		fmt.Println(err)
		return
	}

	blockhash, err := cli.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		fmt.Println(err)
		return
	}

	builder := solana.NewTransactionBuilder().SetRecentBlockHash(blockhash.Value.Blockhash).SetFeePayer(pk.PublicKey()).AddInstruction(ix)

	tx, err = builder.Build()
	if err != nil {
		fmt.Println(err)
		return
	}

	signers := map[solana.PublicKey]*solana.PrivateKey{}

	// fee payer
	signers[pk.PublicKey()] = &pk

	// validatori
	for _, v := range vals {
		signers[v.PublicKey()] = &v.PrivateKey
	}

	mshSer, err := tx.Message.MarshalBinary()
	if err != nil {
		fmt.Println(err)
		return
	}
	hash := sha256.Sum256(mshSer)

	fmt.Println("SHA256:", hex.EncodeToString(hash[:]))

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		return signers[key]
	})
	if err != nil {
		fmt.Println("POTPIS FAIL", err)
		return
	}

	sig, err = cli.SendTransaction(context.TODO(), tx)
	if err != nil {
		fmt.Println("MJAU1", err)
		return
	}

	sub, err = wsCli.SignatureSubscribe(sig, rpc.CommitmentFinalized)
	if err != nil {
		fmt.Println("MJAU2", err)
		return
	}
	defer sub.Unsubscribe()

	result = <-sub.Response()
	if result.Value.Err != nil {
		err = fmt.Errorf("send tx failed: %v", result.Value.Err)
		return
	}

	balance, err = cli.GetTokenAccountBalance(ctx, perinAta, rpc.CommitmentFinalized)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Vault ATA:", perinAta)
	fmt.Println("Vault balance:", balance.Value.Amount)
	time.Sleep(10 * time.Second)
}
