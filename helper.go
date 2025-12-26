package main

import (
	"context"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/ws"
)

// SolanaClient wraps RPC and WebSocket clients for Solana blockchain interactions.
// It provides methods to execute instructions and manage transactions with
// automatic signature subscription and confirmation.
type SolanaClient struct {
	cli        *rpc.Client
	wsCli      *ws.Client
	commitment rpc.CommitmentType
}

// NewSolanaClient creates a new SolanaClient instance with the provided RPC and WebSocket clients.
// The client is initialized with CommitmentFinalized as the default commitment level.
func NewSolanaClient(cli *rpc.Client, wsCli *ws.Client) *SolanaClient {
	return &SolanaClient{
		cli:        cli,
		wsCli:      wsCli,
		commitment: rpc.CommitmentFinalized,
	}
}

// ExecuteInstruction builds, signs, and sends a transaction containing a single instruction.
// It waits for the transaction to be confirmed using WebSocket subscription.
//
// Parameters:
//   - ix: The instruction to execute
//   - signers: Map of public keys to their corresponding private keys for signing
//   - feePayer: The public key of the account that will pay for the transaction fees
//
// Returns the transaction signature on success, or an error if any step fails.
func (s *SolanaClient) ExecuteInstruction(
	ix *solana.Instruction,
	signers map[solana.PublicKey]*solana.PrivateKey,
	feePayer solana.PrivateKey,
) (*solana.Signature, error) {
	blockhash, err := s.cli.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest blockhash: %w", err)
	}

	tx, err := solana.NewTransactionBuilder().
		SetRecentBlockHash(blockhash.Value.Blockhash).
		SetFeePayer(feePayer.PublicKey()).
		AddInstruction(*ix).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction: %w", err)
	}

	signers[feePayer.PublicKey()] = &feePayer

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		return signers[key]
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	sig, err := s.cli.SendTransaction(context.TODO(), tx)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}

	sub, err := s.wsCli.SignatureSubscribe(sig, s.commitment)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to signature: %w", err)
	}
	defer sub.Unsubscribe()

	result := <-sub.Response()
	if result.Value.Err != nil {
		return nil, fmt.Errorf("send tx failed: %v", result.Value.Err)
	}

	return &sig, nil
}

// ExecuteInstructionWithAccounts executes an instruction with additional account metadata.
// This method merges the instruction's existing accounts with the provided additional accounts
// before building and sending the transaction.
//
// Parameters:
//   - ix: The base instruction to execute
//   - accounts: Additional account metadata to append to the instruction's accounts
//   - signers: Map of public keys to their corresponding private keys for signing
//   - feePayer: The public key of the account that will pay for the transaction fees
//
// Returns the transaction signature on success, or an error if any step fails.
func (s *SolanaClient) ExecuteInstructionWithAccounts(
	ix solana.Instruction,
	accounts []*solana.AccountMeta,
	signers map[solana.PublicKey]*solana.PrivateKey,
	feePayer solana.PrivateKey,
) (*solana.Signature, error) {
	blockhash, err := s.cli.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest blockhash: %w", err)
	}

	ixAccounts := append(ix.Accounts(), accounts...)

	data, err := ix.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to get instruction data: %w", err)
	}

	tx, err := solana.NewTransactionBuilder().
		SetRecentBlockHash(blockhash.Value.Blockhash).
		SetFeePayer(feePayer.PublicKey()).
		AddInstruction(solana.NewInstruction(ix.ProgramID(), ixAccounts, data)).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction: %w", err)
	}

	signers[feePayer.PublicKey()] = &feePayer

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		return signers[key]
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	sig, err := s.cli.SendTransaction(context.TODO(), tx)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}

	sub, err := s.wsCli.SignatureSubscribe(sig, s.commitment)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to signature: %w", err)
	}
	defer sub.Unsubscribe()

	result := <-sub.Response()
	if result.Value.Err != nil {
		return nil, fmt.Errorf("send tx failed: %v", result.Value.Err)
	}

	return &sig, nil
}

// CreateInstructionWithAccounts creates a new instruction by merging the provided instruction's
// accounts with additional account metadata. This is a utility method that does not execute
// the instruction, only constructs it.
//
// Parameters:
//   - ix: The base instruction
//   - accounts: Additional account metadata to append to the instruction's accounts
//
// Returns a new instruction with merged accounts, or an error if the instruction data cannot be retrieved.
func (s *SolanaClient) CreateInstructionWithAccounts(
	ix solana.Instruction,
	accounts []*solana.AccountMeta,
) (solana.Instruction, error) {
	data, err := ix.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to get instruction data: %w", err)
	}

	return solana.NewInstruction(ix.ProgramID(), append(ix.Accounts(), accounts...), data), nil
}

// ExecuteMultipleInstructions builds, signs, and sends a transaction containing multiple instructions.
// All instructions are included in a single transaction and executed atomically.
// It waits for the transaction to be confirmed using WebSocket subscription.
//
// Parameters:
//   - ixs: Slice of instructions to execute in the transaction
//   - accounts: Additional account metadata (currently unused but kept for API consistency)
//   - signers: Map of public keys to their corresponding private keys for signing
//   - feePayer: The public key of the account that will pay for the transaction fees
//
// Returns the transaction signature on success, or an error if any step fails.
func (s *SolanaClient) ExecuteMultipleInstructions(
	ixs []solana.Instruction,
	accounts []*solana.AccountMeta,
	signers map[solana.PublicKey]*solana.PrivateKey,
	feePayer solana.PrivateKey,
) (*solana.Signature, error) {
	blockhash, err := s.cli.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest blockhash: %w", err)
	}

	builder := solana.NewTransactionBuilder().
		SetRecentBlockHash(blockhash.Value.Blockhash).
		SetFeePayer(feePayer.PublicKey())

	for _, ix := range ixs {
		builder.AddInstruction(ix)
	}

	tx, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction: %w", err)
	}

	signers[feePayer.PublicKey()] = &feePayer

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		return signers[key]
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	sig, err := s.cli.SendTransaction(context.TODO(), tx)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}

	sub, err := s.wsCli.SignatureSubscribe(sig, s.commitment)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to signature: %w", err)
	}
	defer sub.Unsubscribe()

	result := <-sub.Response()
	if result.Value.Err != nil {
		return nil, fmt.Errorf("send tx failed: %v", result.Value.Err)
	}

	return &sig, nil
}
